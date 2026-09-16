rule TTP_XOR_MULT_DOSStub_26a4 {
  strings:
    $key_26a4 = { 72 cc [2] 06 d4 [2] 41 d6 [2] 06 c7 [2] 48 cb [2] 44 c1 [2] 53 ca [2] 48 84 [2] 75 }

  condition:
    any of them
}