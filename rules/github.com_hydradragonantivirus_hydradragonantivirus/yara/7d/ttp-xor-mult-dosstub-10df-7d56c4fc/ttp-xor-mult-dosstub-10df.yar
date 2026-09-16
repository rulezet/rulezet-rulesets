rule TTP_XOR_MULT_DOSStub_10df {
  strings:
    $key_10df = { 44 b7 [2] 30 af [2] 77 ad [2] 30 bc [2] 7e b0 [2] 72 ba [2] 65 b1 [2] 7e ff [2] 43 }

  condition:
    any of them
}