rule TTP_XOR_MULT_DOSStub_6bc8 {
  strings:
    $key_6bc8 = { 3f a0 [2] 4b b8 [2] 0c ba [2] 4b ab [2] 05 a7 [2] 09 ad [2] 1e a6 [2] 05 e8 [2] 38 }

  condition:
    any of them
}