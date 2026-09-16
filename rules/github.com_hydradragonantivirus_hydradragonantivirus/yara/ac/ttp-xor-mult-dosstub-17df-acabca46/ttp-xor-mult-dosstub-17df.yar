rule TTP_XOR_MULT_DOSStub_17df {
  strings:
    $key_17df = { 43 b7 [2] 37 af [2] 70 ad [2] 37 bc [2] 79 b0 [2] 75 ba [2] 62 b1 [2] 79 ff [2] 44 }

  condition:
    any of them
}