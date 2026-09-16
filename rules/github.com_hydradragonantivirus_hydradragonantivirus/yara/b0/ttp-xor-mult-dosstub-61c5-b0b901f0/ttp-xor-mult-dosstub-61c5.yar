rule TTP_XOR_MULT_DOSStub_61c5 {
  strings:
    $key_61c5 = { 35 ad [2] 41 b5 [2] 06 b7 [2] 41 a6 [2] 0f aa [2] 03 a0 [2] 14 ab [2] 0f e5 [2] 32 }

  condition:
    any of them
}