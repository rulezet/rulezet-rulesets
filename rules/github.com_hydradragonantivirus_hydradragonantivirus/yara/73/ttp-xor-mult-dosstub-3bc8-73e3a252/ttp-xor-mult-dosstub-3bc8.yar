rule TTP_XOR_MULT_DOSStub_3bc8 {
  strings:
    $key_3bc8 = { 6f a0 [2] 1b b8 [2] 5c ba [2] 1b ab [2] 55 a7 [2] 59 ad [2] 4e a6 [2] 55 e8 [2] 68 }

  condition:
    any of them
}