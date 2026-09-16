rule TTP_XOR_MULT_DOSStub_28ae {
  strings:
    $key_28ae = { 7c c6 [2] 08 de [2] 4f dc [2] 08 cd [2] 46 c1 [2] 4a cb [2] 5d c0 [2] 46 8e [2] 7b }

  condition:
    any of them
}