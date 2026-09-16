rule TTP_XOR_MULT_DOSStub_e8ca {
  strings:
    $key_e8ca = { bc a2 [2] c8 ba [2] 8f b8 [2] c8 a9 [2] 86 a5 [2] 8a af [2] 9d a4 [2] 86 ea [2] bb }

  condition:
    any of them
}