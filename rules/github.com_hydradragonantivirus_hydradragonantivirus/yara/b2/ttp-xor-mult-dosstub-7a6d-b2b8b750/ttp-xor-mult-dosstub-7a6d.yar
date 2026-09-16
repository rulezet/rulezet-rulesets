rule TTP_XOR_MULT_DOSStub_7a6d {
  strings:
    $key_7a6d = { 2e 05 [2] 5a 1d [2] 1d 1f [2] 5a 0e [2] 14 02 [2] 18 08 [2] 0f 03 [2] 14 4d [2] 29 }

  condition:
    any of them
}