rule TTP_XOR_MULT_DOSStub_0351 {
  strings:
    $key_0351 = { 57 39 [2] 23 21 [2] 64 23 [2] 23 32 [2] 6d 3e [2] 61 34 [2] 76 3f [2] 6d 71 [2] 50 }

  condition:
    any of them
}