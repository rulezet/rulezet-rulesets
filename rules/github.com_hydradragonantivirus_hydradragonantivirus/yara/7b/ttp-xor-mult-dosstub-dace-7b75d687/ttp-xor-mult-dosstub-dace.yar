rule TTP_XOR_MULT_DOSStub_dace {
  strings:
    $key_dace = { 8e a6 [2] fa be [2] bd bc [2] fa ad [2] b4 a1 [2] b8 ab [2] af a0 [2] b4 ee [2] 89 }

  condition:
    any of them
}