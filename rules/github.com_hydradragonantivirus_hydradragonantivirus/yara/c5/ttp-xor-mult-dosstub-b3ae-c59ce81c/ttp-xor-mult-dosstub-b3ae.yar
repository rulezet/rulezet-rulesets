rule TTP_XOR_MULT_DOSStub_b3ae {
  strings:
    $key_b3ae = { e7 c6 [2] 93 de [2] d4 dc [2] 93 cd [2] dd c1 [2] d1 cb [2] c6 c0 [2] dd 8e [2] e0 }

  condition:
    any of them
}