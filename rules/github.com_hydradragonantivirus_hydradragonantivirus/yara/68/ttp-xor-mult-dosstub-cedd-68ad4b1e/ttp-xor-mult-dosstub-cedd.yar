rule TTP_XOR_MULT_DOSStub_cedd {
  strings:
    $key_cedd = { 9a b5 [2] ee ad [2] a9 af [2] ee be [2] a0 b2 [2] ac b8 [2] bb b3 [2] a0 fd [2] 9d }

  condition:
    any of them
}