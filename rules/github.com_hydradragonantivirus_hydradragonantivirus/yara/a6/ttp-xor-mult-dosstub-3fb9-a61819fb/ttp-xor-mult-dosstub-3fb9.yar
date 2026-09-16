rule TTP_XOR_MULT_DOSStub_3fb9 {
  strings:
    $key_3fb9 = { 6b d1 [2] 1f c9 [2] 58 cb [2] 1f da [2] 51 d6 [2] 5d dc [2] 4a d7 [2] 51 99 [2] 6c }

  condition:
    any of them
}