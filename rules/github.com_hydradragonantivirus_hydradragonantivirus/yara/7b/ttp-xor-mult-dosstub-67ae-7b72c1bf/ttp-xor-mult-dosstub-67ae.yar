rule TTP_XOR_MULT_DOSStub_67ae {
  strings:
    $key_67ae = { 33 c6 [2] 47 de [2] 00 dc [2] 47 cd [2] 09 c1 [2] 05 cb [2] 12 c0 [2] 09 8e [2] 34 }

  condition:
    any of them
}