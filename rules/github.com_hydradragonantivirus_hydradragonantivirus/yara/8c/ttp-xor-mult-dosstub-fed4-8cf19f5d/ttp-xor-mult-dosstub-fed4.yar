rule TTP_XOR_MULT_DOSStub_fed4 {
  strings:
    $key_fed4 = { aa bc [2] de a4 [2] 99 a6 [2] de b7 [2] 90 bb [2] 9c b1 [2] 8b ba [2] 90 f4 [2] ad }

  condition:
    any of them
}