rule TTP_XOR_MULT_DOSStub_06a4 {
  strings:
    $key_06a4 = { 52 cc [2] 26 d4 [2] 61 d6 [2] 26 c7 [2] 68 cb [2] 64 c1 [2] 73 ca [2] 68 84 [2] 55 }

  condition:
    any of them
}