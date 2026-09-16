rule TTP_XOR_MULT_DOSStub_50df {
  strings:
    $key_50df = { 04 b7 [2] 70 af [2] 37 ad [2] 70 bc [2] 3e b0 [2] 32 ba [2] 25 b1 [2] 3e ff [2] 03 }

  condition:
    any of them
}