rule TTP_XOR_MULT_DOSStub_ea96 {
  strings:
    $key_ea96 = { be fe [2] ca e6 [2] 8d e4 [2] ca f5 [2] 84 f9 [2] 88 f3 [2] 9f f8 [2] 84 b6 [2] b9 }

  condition:
    any of them
}