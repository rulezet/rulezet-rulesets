rule TTP_XOR_MULT_DOSStub_1ca2 {
  strings:
    $key_1ca2 = { 48 ca [2] 3c d2 [2] 7b d0 [2] 3c c1 [2] 72 cd [2] 7e c7 [2] 69 cc [2] 72 82 [2] 4f }

  condition:
    any of them
}