rule TTP_XOR_MULT_DOSStub_f7a7 {
  strings:
    $key_f7a7 = { a3 cf [2] d7 d7 [2] 90 d5 [2] d7 c4 [2] 99 c8 [2] 95 c2 [2] 82 c9 [2] 99 87 [2] a4 }

  condition:
    any of them
}