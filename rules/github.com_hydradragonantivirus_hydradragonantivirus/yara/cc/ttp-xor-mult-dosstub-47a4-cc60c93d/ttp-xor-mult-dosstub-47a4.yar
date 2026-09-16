rule TTP_XOR_MULT_DOSStub_47a4 {
  strings:
    $key_47a4 = { 13 cc [2] 67 d4 [2] 20 d6 [2] 67 c7 [2] 29 cb [2] 25 c1 [2] 32 ca [2] 29 84 [2] 14 }

  condition:
    any of them
}