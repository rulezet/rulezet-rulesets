rule TTP_XOR_MULT_DOSStub_61a4 {
  strings:
    $key_61a4 = { 35 cc [2] 41 d4 [2] 06 d6 [2] 41 c7 [2] 0f cb [2] 03 c1 [2] 14 ca [2] 0f 84 [2] 32 }

  condition:
    any of them
}