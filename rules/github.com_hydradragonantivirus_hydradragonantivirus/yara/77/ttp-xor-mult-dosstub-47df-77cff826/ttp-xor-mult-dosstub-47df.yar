rule TTP_XOR_MULT_DOSStub_47df {
  strings:
    $key_47df = { 13 b7 [2] 67 af [2] 20 ad [2] 67 bc [2] 29 b0 [2] 25 ba [2] 32 b1 [2] 29 ff [2] 14 }

  condition:
    any of them
}