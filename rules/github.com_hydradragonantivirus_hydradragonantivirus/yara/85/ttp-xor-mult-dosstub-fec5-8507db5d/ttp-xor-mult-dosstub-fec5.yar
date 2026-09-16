rule TTP_XOR_MULT_DOSStub_fec5 {
  strings:
    $key_fec5 = { aa ad [2] de b5 [2] 99 b7 [2] de a6 [2] 90 aa [2] 9c a0 [2] 8b ab [2] 90 e5 [2] ad }

  condition:
    any of them
}