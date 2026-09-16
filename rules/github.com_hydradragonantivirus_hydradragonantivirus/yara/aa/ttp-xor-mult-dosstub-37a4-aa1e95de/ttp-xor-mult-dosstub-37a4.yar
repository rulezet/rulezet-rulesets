rule TTP_XOR_MULT_DOSStub_37a4 {
  strings:
    $key_37a4 = { 63 cc [2] 17 d4 [2] 50 d6 [2] 17 c7 [2] 59 cb [2] 55 c1 [2] 42 ca [2] 59 84 [2] 64 }

  condition:
    any of them
}