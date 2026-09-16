rule TTP_XOR_MULT_DOSStub_f6a7 {
  strings:
    $key_f6a7 = { a2 cf [2] d6 d7 [2] 91 d5 [2] d6 c4 [2] 98 c8 [2] 94 c2 [2] 83 c9 [2] 98 87 [2] a5 }

  condition:
    any of them
}