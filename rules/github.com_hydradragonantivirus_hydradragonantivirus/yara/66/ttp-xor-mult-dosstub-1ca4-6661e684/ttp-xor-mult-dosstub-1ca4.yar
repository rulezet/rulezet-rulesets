rule TTP_XOR_MULT_DOSStub_1ca4 {
  strings:
    $key_1ca4 = { 48 cc [2] 3c d4 [2] 7b d6 [2] 3c c7 [2] 72 cb [2] 7e c1 [2] 69 ca [2] 72 84 [2] 4f }

  condition:
    any of them
}