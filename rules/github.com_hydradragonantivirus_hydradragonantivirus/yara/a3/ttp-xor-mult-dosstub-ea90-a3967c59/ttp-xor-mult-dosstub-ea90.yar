rule TTP_XOR_MULT_DOSStub_ea90 {
  strings:
    $key_ea90 = { be f8 [2] ca e0 [2] 8d e2 [2] ca f3 [2] 84 ff [2] 88 f5 [2] 9f fe [2] 84 b0 [2] b9 }

  condition:
    any of them
}