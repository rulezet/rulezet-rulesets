rule TTP_XOR_MULT_DOSStub_cfca {
  strings:
    $key_cfca = { 9b a2 [2] ef ba [2] a8 b8 [2] ef a9 [2] a1 a5 [2] ad af [2] ba a4 [2] a1 ea [2] 9c }

  condition:
    any of them
}