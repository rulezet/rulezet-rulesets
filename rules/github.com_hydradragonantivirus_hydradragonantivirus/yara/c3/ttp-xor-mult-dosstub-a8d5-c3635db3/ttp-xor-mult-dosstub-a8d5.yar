rule TTP_XOR_MULT_DOSStub_a8d5 {
  strings:
    $key_a8d5 = { fc bd [2] 88 a5 [2] cf a7 [2] 88 b6 [2] c6 ba [2] ca b0 [2] dd bb [2] c6 f5 [2] fb }

  condition:
    any of them
}