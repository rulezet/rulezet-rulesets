rule TTP_XOR_MULT_DOSStub_6edd {
  strings:
    $key_6edd = { 3a b5 [2] 4e ad [2] 09 af [2] 4e be [2] 00 b2 [2] 0c b8 [2] 1b b3 [2] 00 fd [2] 3d }

  condition:
    any of them
}