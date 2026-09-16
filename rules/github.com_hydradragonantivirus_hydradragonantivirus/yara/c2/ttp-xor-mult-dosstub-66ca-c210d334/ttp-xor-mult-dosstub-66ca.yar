rule TTP_XOR_MULT_DOSStub_66ca {
  strings:
    $key_66ca = { 32 a2 [2] 46 ba [2] 01 b8 [2] 46 a9 [2] 08 a5 [2] 04 af [2] 13 a4 [2] 08 ea [2] 35 }

  condition:
    any of them
}