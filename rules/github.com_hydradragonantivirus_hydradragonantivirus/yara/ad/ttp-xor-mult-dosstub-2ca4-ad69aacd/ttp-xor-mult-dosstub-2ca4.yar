rule TTP_XOR_MULT_DOSStub_2ca4 {
  strings:
    $key_2ca4 = { 78 cc [2] 0c d4 [2] 4b d6 [2] 0c c7 [2] 42 cb [2] 4e c1 [2] 59 ca [2] 42 84 [2] 7f }

  condition:
    any of them
}