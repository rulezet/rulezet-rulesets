rule TTP_XOR_MULT_DOSStub_46ae {
  strings:
    $key_46ae = { 12 c6 [2] 66 de [2] 21 dc [2] 66 cd [2] 28 c1 [2] 24 cb [2] 33 c0 [2] 28 8e [2] 15 }

  condition:
    any of them
}