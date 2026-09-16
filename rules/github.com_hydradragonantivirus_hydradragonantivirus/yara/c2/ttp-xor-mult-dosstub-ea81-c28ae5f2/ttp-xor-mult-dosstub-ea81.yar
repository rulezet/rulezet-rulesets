rule TTP_XOR_MULT_DOSStub_ea81 {
  strings:
    $key_ea81 = { be e9 [2] ca f1 [2] 8d f3 [2] ca e2 [2] 84 ee [2] 88 e4 [2] 9f ef [2] 84 a1 [2] b9 }

  condition:
    any of them
}