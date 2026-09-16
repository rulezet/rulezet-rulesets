rule TTP_XOR_MULT_DOSStub_61a0 {
  strings:
    $key_61a0 = { 35 c8 [2] 41 d0 [2] 06 d2 [2] 41 c3 [2] 0f cf [2] 03 c5 [2] 14 ce [2] 0f 80 [2] 32 }

  condition:
    any of them
}