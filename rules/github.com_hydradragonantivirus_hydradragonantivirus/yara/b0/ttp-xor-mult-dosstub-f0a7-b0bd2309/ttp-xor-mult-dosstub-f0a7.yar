rule TTP_XOR_MULT_DOSStub_f0a7 {
  strings:
    $key_f0a7 = { a4 cf [2] d0 d7 [2] 97 d5 [2] d0 c4 [2] 9e c8 [2] 92 c2 [2] 85 c9 [2] 9e 87 [2] a3 }

  condition:
    any of them
}