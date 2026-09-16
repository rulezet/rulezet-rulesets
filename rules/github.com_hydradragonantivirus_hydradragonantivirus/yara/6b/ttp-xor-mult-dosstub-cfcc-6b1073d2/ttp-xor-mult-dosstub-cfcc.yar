rule TTP_XOR_MULT_DOSStub_cfcc {
  strings:
    $key_cfcc = { 9b a4 [2] ef bc [2] a8 be [2] ef af [2] a1 a3 [2] ad a9 [2] ba a2 [2] a1 ec [2] 9c }

  condition:
    any of them
}