rule TTP_XOR_MULT_DOSStub_eca7 {
  strings:
    $key_eca7 = { b8 cf [2] cc d7 [2] 8b d5 [2] cc c4 [2] 82 c8 [2] 8e c2 [2] 99 c9 [2] 82 87 [2] bf }

  condition:
    any of them
}