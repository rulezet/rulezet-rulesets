rule TTP_XOR_MULT_DOSStub_23df {
  strings:
    $key_23df = { 77 b7 [2] 03 af [2] 44 ad [2] 03 bc [2] 4d b0 [2] 41 ba [2] 56 b1 [2] 4d ff [2] 70 }

  condition:
    any of them
}