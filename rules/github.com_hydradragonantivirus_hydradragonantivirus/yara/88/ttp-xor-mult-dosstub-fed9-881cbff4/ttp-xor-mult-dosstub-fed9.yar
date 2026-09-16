rule TTP_XOR_MULT_DOSStub_fed9 {
  strings:
    $key_fed9 = { aa b1 [2] de a9 [2] 99 ab [2] de ba [2] 90 b6 [2] 9c bc [2] 8b b7 [2] 90 f9 [2] ad }

  condition:
    any of them
}