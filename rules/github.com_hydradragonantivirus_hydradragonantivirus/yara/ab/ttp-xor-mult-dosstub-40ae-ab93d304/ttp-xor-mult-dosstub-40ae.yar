rule TTP_XOR_MULT_DOSStub_40ae {
  strings:
    $key_40ae = { 14 c6 [2] 60 de [2] 27 dc [2] 60 cd [2] 2e c1 [2] 22 cb [2] 35 c0 [2] 2e 8e [2] 13 }

  condition:
    any of them
}