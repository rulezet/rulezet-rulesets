rule TTP_XOR_MULT_DOSStub_58ae {
  strings:
    $key_58ae = { 0c c6 [2] 78 de [2] 3f dc [2] 78 cd [2] 36 c1 [2] 3a cb [2] 2d c0 [2] 36 8e [2] 0b }

  condition:
    any of them
}