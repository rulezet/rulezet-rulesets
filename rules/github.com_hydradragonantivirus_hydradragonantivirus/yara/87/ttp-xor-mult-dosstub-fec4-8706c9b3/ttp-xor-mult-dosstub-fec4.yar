rule TTP_XOR_MULT_DOSStub_fec4 {
  strings:
    $key_fec4 = { aa ac [2] de b4 [2] 99 b6 [2] de a7 [2] 90 ab [2] 9c a1 [2] 8b aa [2] 90 e4 [2] ad }

  condition:
    any of them
}