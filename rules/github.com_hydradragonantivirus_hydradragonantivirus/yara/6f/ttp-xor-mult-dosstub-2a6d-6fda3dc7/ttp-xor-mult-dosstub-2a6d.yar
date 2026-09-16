rule TTP_XOR_MULT_DOSStub_2a6d {
  strings:
    $key_2a6d = { 7e 05 [2] 0a 1d [2] 4d 1f [2] 0a 0e [2] 44 02 [2] 48 08 [2] 5f 03 [2] 44 4d [2] 79 }

  condition:
    any of them
}