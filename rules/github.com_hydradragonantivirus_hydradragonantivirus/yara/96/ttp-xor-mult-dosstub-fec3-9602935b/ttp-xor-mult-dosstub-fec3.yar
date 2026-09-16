rule TTP_XOR_MULT_DOSStub_fec3 {
  strings:
    $key_fec3 = { aa ab [2] de b3 [2] 99 b1 [2] de a0 [2] 90 ac [2] 9c a6 [2] 8b ad [2] 90 e3 [2] ad }

  condition:
    any of them
}