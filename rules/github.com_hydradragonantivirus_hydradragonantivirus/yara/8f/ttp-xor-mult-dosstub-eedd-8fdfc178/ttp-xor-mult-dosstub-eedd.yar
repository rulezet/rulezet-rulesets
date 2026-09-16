rule TTP_XOR_MULT_DOSStub_eedd {
  strings:
    $key_eedd = { ba b5 [2] ce ad [2] 89 af [2] ce be [2] 80 b2 [2] 8c b8 [2] 9b b3 [2] 80 fd [2] bd }

  condition:
    any of them
}