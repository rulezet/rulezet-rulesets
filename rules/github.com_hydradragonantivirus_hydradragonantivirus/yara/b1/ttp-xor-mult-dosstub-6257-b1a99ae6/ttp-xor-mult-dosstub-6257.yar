rule TTP_XOR_MULT_DOSStub_6257 {
  strings:
    $key_6257 = { 36 3f [2] 42 27 [2] 05 25 [2] 42 34 [2] 0c 38 [2] 00 32 [2] 17 39 [2] 0c 77 [2] 31 }

  condition:
    any of them
}