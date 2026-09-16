rule TTP_XOR_MULT_DOSStub_fedd {
  strings:
    $key_fedd = { aa b5 [2] de ad [2] 99 af [2] de be [2] 90 b2 [2] 9c b8 [2] 8b b3 [2] 90 fd [2] ad }

  condition:
    any of them
}