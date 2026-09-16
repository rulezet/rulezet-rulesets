rule TTP_XOR_MULT_DOSStub_68ae {
  strings:
    $key_68ae = { 3c c6 [2] 48 de [2] 0f dc [2] 48 cd [2] 06 c1 [2] 0a cb [2] 1d c0 [2] 06 8e [2] 3b }

  condition:
    any of them
}