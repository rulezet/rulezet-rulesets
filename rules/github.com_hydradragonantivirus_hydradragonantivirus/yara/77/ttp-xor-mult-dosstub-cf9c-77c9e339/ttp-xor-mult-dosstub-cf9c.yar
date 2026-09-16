rule TTP_XOR_MULT_DOSStub_cf9c {
  strings:
    $key_cf9c = { 9b f4 [2] ef ec [2] a8 ee [2] ef ff [2] a1 f3 [2] ad f9 [2] ba f2 [2] a1 bc [2] 9c }

  condition:
    any of them
}