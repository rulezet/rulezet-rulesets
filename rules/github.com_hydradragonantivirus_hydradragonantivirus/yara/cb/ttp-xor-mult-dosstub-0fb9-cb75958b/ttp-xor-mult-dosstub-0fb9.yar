rule TTP_XOR_MULT_DOSStub_0fb9 {
  strings:
    $key_0fb9 = { 5b d1 [2] 2f c9 [2] 68 cb [2] 2f da [2] 61 d6 [2] 6d dc [2] 7a d7 [2] 61 99 [2] 5c }

  condition:
    any of them
}