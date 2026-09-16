rule TTP_XOR_MULT_DOSStub_3bd3 {
  strings:
    $key_3bd3 = { 6f bb [2] 1b a3 [2] 5c a1 [2] 1b b0 [2] 55 bc [2] 59 b6 [2] 4e bd [2] 55 f3 [2] 68 }

  condition:
    any of them
}