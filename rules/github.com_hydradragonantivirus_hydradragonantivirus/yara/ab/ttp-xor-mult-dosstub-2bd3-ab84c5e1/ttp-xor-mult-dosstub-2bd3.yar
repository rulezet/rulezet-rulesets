rule TTP_XOR_MULT_DOSStub_2bd3 {
  strings:
    $key_2bd3 = { 7f bb [2] 0b a3 [2] 4c a1 [2] 0b b0 [2] 45 bc [2] 49 b6 [2] 5e bd [2] 45 f3 [2] 78 }

  condition:
    any of them
}