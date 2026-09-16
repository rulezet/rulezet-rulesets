rule TTP_XOR_MULT_DOSStub_7fb9 {
  strings:
    $key_7fb9 = { 2b d1 [2] 5f c9 [2] 18 cb [2] 5f da [2] 11 d6 [2] 1d dc [2] 0a d7 [2] 11 99 [2] 2c }

  condition:
    any of them
}