rule TTP_XOR_MULT_DOSStub_ead4 {
  strings:
    $key_ead4 = { be bc [2] ca a4 [2] 8d a6 [2] ca b7 [2] 84 bb [2] 88 b1 [2] 9f ba [2] 84 f4 [2] b9 }

  condition:
    any of them
}