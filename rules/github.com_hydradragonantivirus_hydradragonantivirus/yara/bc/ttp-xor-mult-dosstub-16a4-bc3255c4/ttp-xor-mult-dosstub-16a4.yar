rule TTP_XOR_MULT_DOSStub_16a4 {
  strings:
    $key_16a4 = { 42 cc [2] 36 d4 [2] 71 d6 [2] 36 c7 [2] 78 cb [2] 74 c1 [2] 63 ca [2] 78 84 [2] 45 }

  condition:
    any of them
}