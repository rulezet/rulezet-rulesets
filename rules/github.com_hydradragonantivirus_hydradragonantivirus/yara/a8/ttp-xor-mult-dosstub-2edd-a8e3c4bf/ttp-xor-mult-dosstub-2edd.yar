rule TTP_XOR_MULT_DOSStub_2edd {
  strings:
    $key_2edd = { 7a b5 [2] 0e ad [2] 49 af [2] 0e be [2] 40 b2 [2] 4c b8 [2] 5b b3 [2] 40 fd [2] 7d }

  condition:
    any of them
}