rule TTP_XOR_MULT_DOSStub_00a4 {
  strings:
    $key_00a4 = { 54 cc [2] 20 d4 [2] 67 d6 [2] 20 c7 [2] 6e cb [2] 62 c1 [2] 75 ca [2] 6e 84 [2] 53 }

  condition:
    any of them
}