rule TTP_XOR_MULT_DOSStub_04ae {
  strings:
    $key_04ae = { 50 c6 [2] 24 de [2] 63 dc [2] 24 cd [2] 6a c1 [2] 66 cb [2] 71 c0 [2] 6a 8e [2] 57 }

  condition:
    any of them
}