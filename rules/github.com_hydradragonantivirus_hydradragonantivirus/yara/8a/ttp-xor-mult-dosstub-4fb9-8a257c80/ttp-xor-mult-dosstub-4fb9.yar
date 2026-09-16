rule TTP_XOR_MULT_DOSStub_4fb9 {
  strings:
    $key_4fb9 = { 1b d1 [2] 6f c9 [2] 28 cb [2] 6f da [2] 21 d6 [2] 2d dc [2] 3a d7 [2] 21 99 [2] 1c }

  condition:
    any of them
}