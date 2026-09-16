rule TTP_XOR_MULT_DOSStub_20df {
  strings:
    $key_20df = { 74 b7 [2] 00 af [2] 47 ad [2] 00 bc [2] 4e b0 [2] 42 ba [2] 55 b1 [2] 4e ff [2] 73 }

  condition:
    any of them
}