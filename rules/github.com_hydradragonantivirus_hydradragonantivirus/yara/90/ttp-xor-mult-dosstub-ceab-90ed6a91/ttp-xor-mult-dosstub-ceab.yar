rule TTP_XOR_MULT_DOSStub_ceab {
  strings:
    $key_ceab = { 9a c3 [2] ee db [2] a9 d9 [2] ee c8 [2] a0 c4 [2] ac ce [2] bb c5 [2] a0 8b [2] 9d }

  condition:
    any of them
}