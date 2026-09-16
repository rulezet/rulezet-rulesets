rule TTP_XOR_MULT_DOSStub_3ca8 {
  strings:
    $key_3ca8 = { 68 c0 [2] 1c d8 [2] 5b da [2] 1c cb [2] 52 c7 [2] 5e cd [2] 49 c6 [2] 52 88 [2] 6f }

  condition:
    any of them
}