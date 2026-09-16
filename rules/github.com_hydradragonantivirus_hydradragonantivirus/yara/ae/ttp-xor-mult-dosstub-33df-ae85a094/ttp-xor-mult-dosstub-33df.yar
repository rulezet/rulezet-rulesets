rule TTP_XOR_MULT_DOSStub_33df {
  strings:
    $key_33df = { 67 b7 [2] 13 af [2] 54 ad [2] 13 bc [2] 5d b0 [2] 51 ba [2] 46 b1 [2] 5d ff [2] 60 }

  condition:
    any of them
}