rule TTP_XOR_MULT_DOSStub_4edd {
  strings:
    $key_4edd = { 1a b5 [2] 6e ad [2] 29 af [2] 6e be [2] 20 b2 [2] 2c b8 [2] 3b b3 [2] 20 fd [2] 1d }

  condition:
    any of them
}