rule TTP_XOR_MULT_DOSStub_da95 {
  strings:
    $key_da95 = { 8e fd [2] fa e5 [2] bd e7 [2] fa f6 [2] b4 fa [2] b8 f0 [2] af fb [2] b4 b5 [2] 89 }

  condition:
    any of them
}