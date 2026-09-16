rule TTP_XOR_MULT_DOSStub_76ae {
  strings:
    $key_76ae = { 22 c6 [2] 56 de [2] 11 dc [2] 56 cd [2] 18 c1 [2] 14 cb [2] 03 c0 [2] 18 8e [2] 25 }

  condition:
    any of them
}