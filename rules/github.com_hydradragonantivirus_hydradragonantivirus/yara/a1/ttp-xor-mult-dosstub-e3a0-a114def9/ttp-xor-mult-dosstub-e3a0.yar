rule TTP_XOR_MULT_DOSStub_e3a0 {
  strings:
    $key_e3a0 = { b7 c8 [2] c3 d0 [2] 84 d2 [2] c3 c3 [2] 8d cf [2] 81 c5 [2] 96 ce [2] 8d 80 [2] b0 }

  condition:
    any of them
}