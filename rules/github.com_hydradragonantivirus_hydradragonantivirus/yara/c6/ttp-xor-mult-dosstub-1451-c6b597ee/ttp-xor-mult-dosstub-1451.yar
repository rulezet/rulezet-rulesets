rule TTP_XOR_MULT_DOSStub_1451 {
  strings:
    $key_1451 = { 40 39 [2] 34 21 [2] 73 23 [2] 34 32 [2] 7a 3e [2] 76 34 [2] 61 3f [2] 7a 71 [2] 47 }

  condition:
    any of them
}