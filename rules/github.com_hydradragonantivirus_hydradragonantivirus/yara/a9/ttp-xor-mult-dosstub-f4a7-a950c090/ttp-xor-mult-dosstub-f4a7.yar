rule TTP_XOR_MULT_DOSStub_f4a7 {
  strings:
    $key_f4a7 = { a0 cf [2] d4 d7 [2] 93 d5 [2] d4 c4 [2] 9a c8 [2] 96 c2 [2] 81 c9 [2] 9a 87 [2] a7 }

  condition:
    any of them
}