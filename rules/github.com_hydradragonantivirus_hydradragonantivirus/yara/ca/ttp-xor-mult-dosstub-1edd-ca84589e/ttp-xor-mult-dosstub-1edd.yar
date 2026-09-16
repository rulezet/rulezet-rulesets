rule TTP_XOR_MULT_DOSStub_1edd {
  strings:
    $key_1edd = { 4a b5 [2] 3e ad [2] 79 af [2] 3e be [2] 70 b2 [2] 7c b8 [2] 6b b3 [2] 70 fd [2] 4d }

  condition:
    any of them
}