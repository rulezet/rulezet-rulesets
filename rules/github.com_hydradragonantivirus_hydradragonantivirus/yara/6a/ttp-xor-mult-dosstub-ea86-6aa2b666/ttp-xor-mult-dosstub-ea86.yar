rule TTP_XOR_MULT_DOSStub_ea86 {
  strings:
    $key_ea86 = { be ee [2] ca f6 [2] 8d f4 [2] ca e5 [2] 84 e9 [2] 88 e3 [2] 9f e8 [2] 84 a6 [2] b9 }

  condition:
    any of them
}