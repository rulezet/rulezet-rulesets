rule TTP_XOR_MULT_DOSStub_dca0 {
  strings:
    $key_dca0 = { 88 c8 [2] fc d0 [2] bb d2 [2] fc c3 [2] b2 cf [2] be c5 [2] a9 ce [2] b2 80 [2] 8f }

  condition:
    any of them
}