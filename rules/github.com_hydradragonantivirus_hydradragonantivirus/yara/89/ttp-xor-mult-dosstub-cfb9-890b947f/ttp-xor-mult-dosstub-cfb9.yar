rule TTP_XOR_MULT_DOSStub_cfb9 {
  strings:
    $key_cfb9 = { 9b d1 [2] ef c9 [2] a8 cb [2] ef da [2] a1 d6 [2] ad dc [2] ba d7 [2] a1 99 [2] 9c }

  condition:
    any of them
}