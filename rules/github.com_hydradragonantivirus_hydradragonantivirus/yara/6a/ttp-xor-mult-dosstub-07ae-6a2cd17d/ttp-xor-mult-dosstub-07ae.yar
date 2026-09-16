rule TTP_XOR_MULT_DOSStub_07ae {
  strings:
    $key_07ae = { 53 c6 [2] 27 de [2] 60 dc [2] 27 cd [2] 69 c1 [2] 65 cb [2] 72 c0 [2] 69 8e [2] 54 }

  condition:
    any of them
}