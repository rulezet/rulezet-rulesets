rule TTP_XOR_MULT_DOSStub_a888 {
  strings:
    $key_a888 = { fc e0 [2] 88 f8 [2] cf fa [2] 88 eb [2] c6 e7 [2] ca ed [2] dd e6 [2] c6 a8 [2] fb }

  condition:
    any of them
}