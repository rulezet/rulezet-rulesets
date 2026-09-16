rule TTP_XOR_MULT_DOSStub_e9dd {
  strings:
    $key_e9dd = { bd b5 [2] c9 ad [2] 8e af [2] c9 be [2] 87 b2 [2] 8b b8 [2] 9c b3 [2] 87 fd [2] ba }

  condition:
    any of them
}