rule TTP_XOR_MULT_DOSStub_e4a7 {
  strings:
    $key_e4a7 = { b0 cf [2] c4 d7 [2] 83 d5 [2] c4 c4 [2] 8a c8 [2] 86 c2 [2] 91 c9 [2] 8a 87 [2] b7 }

  condition:
    any of them
}