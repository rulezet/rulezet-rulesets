rule TTP_XOR_MULT_DOSStub_feca {
  strings:
    $key_feca = { aa a2 [2] de ba [2] 99 b8 [2] de a9 [2] 90 a5 [2] 9c af [2] 8b a4 [2] 90 ea [2] ad }

  condition:
    any of them
}