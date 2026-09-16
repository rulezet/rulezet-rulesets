rule TTP_XOR_MULT_DOSStub_6bd3 {
  strings:
    $key_6bd3 = { 3f bb [2] 4b a3 [2] 0c a1 [2] 4b b0 [2] 05 bc [2] 09 b6 [2] 1e bd [2] 05 f3 [2] 38 }

  condition:
    any of them
}