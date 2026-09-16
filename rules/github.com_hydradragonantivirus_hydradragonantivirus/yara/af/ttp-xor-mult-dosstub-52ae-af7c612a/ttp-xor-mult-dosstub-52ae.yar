rule TTP_XOR_MULT_DOSStub_52ae {
  strings:
    $key_52ae = { 06 c6 [2] 72 de [2] 35 dc [2] 72 cd [2] 3c c1 [2] 30 cb [2] 27 c0 [2] 3c 8e [2] 01 }

  condition:
    any of them
}