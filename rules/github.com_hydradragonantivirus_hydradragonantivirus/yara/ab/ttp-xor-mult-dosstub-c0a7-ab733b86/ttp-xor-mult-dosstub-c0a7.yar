rule TTP_XOR_MULT_DOSStub_c0a7 {
  strings:
    $key_c0a7 = { 94 cf [2] e0 d7 [2] a7 d5 [2] e0 c4 [2] ae c8 [2] a2 c2 [2] b5 c9 [2] ae 87 [2] 93 }

  condition:
    any of them
}