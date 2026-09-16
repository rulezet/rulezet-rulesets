rule TTP_XOR_MULT_DOSStub_6ca4 {
  strings:
    $key_6ca4 = { 38 cc [2] 4c d4 [2] 0b d6 [2] 4c c7 [2] 02 cb [2] 0e c1 [2] 19 ca [2] 02 84 [2] 3f }

  condition:
    any of them
}