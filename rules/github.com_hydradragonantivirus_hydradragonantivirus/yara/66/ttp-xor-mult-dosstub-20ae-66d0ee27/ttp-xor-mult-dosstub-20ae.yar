rule TTP_XOR_MULT_DOSStub_20ae {
  strings:
    $key_20ae = { 74 c6 [2] 00 de [2] 47 dc [2] 00 cd [2] 4e c1 [2] 42 cb [2] 55 c0 [2] 4e 8e [2] 73 }

  condition:
    any of them
}