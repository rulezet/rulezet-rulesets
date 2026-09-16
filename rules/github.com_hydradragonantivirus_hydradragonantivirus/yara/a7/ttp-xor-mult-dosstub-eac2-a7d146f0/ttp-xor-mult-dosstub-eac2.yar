rule TTP_XOR_MULT_DOSStub_eac2 {
  strings:
    $key_eac2 = { be aa [2] ca b2 [2] 8d b0 [2] ca a1 [2] 84 ad [2] 88 a7 [2] 9f ac [2] 84 e2 [2] b9 }

  condition:
    any of them
}