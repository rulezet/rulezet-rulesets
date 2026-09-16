rule TTP_XOR_MULT_DOSStub_72a4 {
  strings:
    $key_72a4 = { 26 cc [2] 52 d4 [2] 15 d6 [2] 52 c7 [2] 1c cb [2] 10 c1 [2] 07 ca [2] 1c 84 [2] 21 }

  condition:
    any of them
}