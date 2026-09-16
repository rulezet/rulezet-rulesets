rule TTP_XOR_MULT_DOSStub_eca0 {
  strings:
    $key_eca0 = { b8 c8 [2] cc d0 [2] 8b d2 [2] cc c3 [2] 82 cf [2] 8e c5 [2] 99 ce [2] 82 80 [2] bf }

  condition:
    any of them
}