rule TTP_XOR_MULT_DOSStub_54ae {
  strings:
    $key_54ae = { 00 c6 [2] 74 de [2] 33 dc [2] 74 cd [2] 3a c1 [2] 36 cb [2] 21 c0 [2] 3a 8e [2] 07 }

  condition:
    any of them
}