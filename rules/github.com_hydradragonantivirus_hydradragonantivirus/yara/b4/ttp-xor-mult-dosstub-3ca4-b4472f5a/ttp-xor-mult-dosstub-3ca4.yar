rule TTP_XOR_MULT_DOSStub_3ca4 {
  strings:
    $key_3ca4 = { 68 cc [2] 1c d4 [2] 5b d6 [2] 1c c7 [2] 52 cb [2] 5e c1 [2] 49 ca [2] 52 84 [2] 6f }

  condition:
    any of them
}