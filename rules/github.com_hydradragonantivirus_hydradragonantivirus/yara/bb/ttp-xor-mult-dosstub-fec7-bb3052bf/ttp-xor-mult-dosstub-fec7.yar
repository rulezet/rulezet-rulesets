rule TTP_XOR_MULT_DOSStub_fec7 {
  strings:
    $key_fec7 = { aa af [2] de b7 [2] 99 b5 [2] de a4 [2] 90 a8 [2] 9c a2 [2] 8b a9 [2] 90 e7 [2] ad }

  condition:
    any of them
}