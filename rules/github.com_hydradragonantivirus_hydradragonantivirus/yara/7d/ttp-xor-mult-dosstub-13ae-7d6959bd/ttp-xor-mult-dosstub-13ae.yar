rule TTP_XOR_MULT_DOSStub_13ae {
  strings:
    $key_13ae = { 47 c6 [2] 33 de [2] 74 dc [2] 33 cd [2] 7d c1 [2] 71 cb [2] 66 c0 [2] 7d 8e [2] 40 }

  condition:
    any of them
}