rule TTP_XOR_MULT_DOSStub_3b6d {
  strings:
    $key_3b6d = { 6f 05 [2] 1b 1d [2] 5c 1f [2] 1b 0e [2] 55 02 [2] 59 08 [2] 4e 03 [2] 55 4d [2] 68 }

  condition:
    any of them
}