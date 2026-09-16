rule TTP_XOR_MULT_DOSStub_63df {
  strings:
    $key_63df = { 37 b7 [2] 43 af [2] 04 ad [2] 43 bc [2] 0d b0 [2] 01 ba [2] 16 b1 [2] 0d ff [2] 30 }

  condition:
    any of them
}