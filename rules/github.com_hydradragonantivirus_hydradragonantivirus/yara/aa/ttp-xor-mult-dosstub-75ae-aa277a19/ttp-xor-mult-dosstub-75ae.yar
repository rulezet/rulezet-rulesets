rule TTP_XOR_MULT_DOSStub_75ae {
  strings:
    $key_75ae = { 21 c6 [2] 55 de [2] 12 dc [2] 55 cd [2] 1b c1 [2] 17 cb [2] 00 c0 [2] 1b 8e [2] 26 }

  condition:
    any of them
}