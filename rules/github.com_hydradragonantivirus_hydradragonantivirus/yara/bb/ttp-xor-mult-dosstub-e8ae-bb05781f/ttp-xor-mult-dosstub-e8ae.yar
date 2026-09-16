rule TTP_XOR_MULT_DOSStub_e8ae {
  strings:
    $key_e8ae = { bc c6 [2] c8 de [2] 8f dc [2] c8 cd [2] 86 c1 [2] 8a cb [2] 9d c0 [2] 86 8e [2] bb }

  condition:
    any of them
}