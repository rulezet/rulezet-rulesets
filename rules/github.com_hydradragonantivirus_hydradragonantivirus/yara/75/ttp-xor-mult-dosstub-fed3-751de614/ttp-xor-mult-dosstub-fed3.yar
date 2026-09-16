rule TTP_XOR_MULT_DOSStub_fed3 {
  strings:
    $key_fed3 = { aa bb [2] de a3 [2] 99 a1 [2] de b0 [2] 90 bc [2] 9c b6 [2] 8b bd [2] 90 f3 [2] ad }

  condition:
    any of them
}