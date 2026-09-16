rule TTP_XOR_MULT_DOSStub_fed0 {
  strings:
    $key_fed0 = { aa b8 [2] de a0 [2] 99 a2 [2] de b3 [2] 90 bf [2] 9c b5 [2] 8b be [2] 90 f0 [2] ad }

  condition:
    any of them
}