rule TTP_XOR_MULT_DOSStub_0bd3 {
  strings:
    $key_0bd3 = { 5f bb [2] 2b a3 [2] 6c a1 [2] 2b b0 [2] 65 bc [2] 69 b6 [2] 7e bd [2] 65 f3 [2] 58 }

  condition:
    any of them
}