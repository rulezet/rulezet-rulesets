rule TTP_XOR_MULT_DOSStub_1257 {
  strings:
    $key_1257 = { 46 3f [2] 32 27 [2] 75 25 [2] 32 34 [2] 7c 38 [2] 70 32 [2] 67 39 [2] 7c 77 [2] 41 }

  condition:
    any of them
}