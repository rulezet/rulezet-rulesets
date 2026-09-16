rule TTP_XOR_MULT_DOSStub_0edd {
  strings:
    $key_0edd = { 5a b5 [2] 2e ad [2] 69 af [2] 2e be [2] 60 b2 [2] 6c b8 [2] 7b b3 [2] 60 fd [2] 5d }

  condition:
    any of them
}