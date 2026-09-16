rule TTP_XOR_MULT_DOSStub_31ae {
  strings:
    $key_31ae = { 65 c6 [2] 11 de [2] 56 dc [2] 11 cd [2] 5f c1 [2] 53 cb [2] 44 c0 [2] 5f 8e [2] 62 }

  condition:
    any of them
}