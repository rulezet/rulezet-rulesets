rule TTP_XOR_MULT_DOSStub_eedf {
  strings:
    $key_eedf = { ba b7 [2] ce af [2] 89 ad [2] ce bc [2] 80 b0 [2] 8c ba [2] 9b b1 [2] 80 ff [2] bd }

  condition:
    any of them
}