rule TTP_XOR_MULT_DOSStub_53df {
  strings:
    $key_53df = { 07 b7 [2] 73 af [2] 34 ad [2] 73 bc [2] 3d b0 [2] 31 ba [2] 26 b1 [2] 3d ff [2] 00 }

  condition:
    any of them
}