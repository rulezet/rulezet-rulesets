rule TTP_XOR_MULT_DOSStub_5451 {
  strings:
    $key_5451 = { 00 39 [2] 74 21 [2] 33 23 [2] 74 32 [2] 3a 3e [2] 36 34 [2] 21 3f [2] 3a 71 [2] 07 }

  condition:
    any of them
}