rule TTP_XOR_MULT_DOSStub_44ae {
  strings:
    $key_44ae = { 10 c6 [2] 64 de [2] 23 dc [2] 64 cd [2] 2a c1 [2] 26 cb [2] 31 c0 [2] 2a 8e [2] 17 }

  condition:
    any of them
}