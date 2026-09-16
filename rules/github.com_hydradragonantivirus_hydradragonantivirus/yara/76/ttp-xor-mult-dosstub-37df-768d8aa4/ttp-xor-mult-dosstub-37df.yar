rule TTP_XOR_MULT_DOSStub_37df {
  strings:
    $key_37df = { 63 b7 [2] 17 af [2] 50 ad [2] 17 bc [2] 59 b0 [2] 55 ba [2] 42 b1 [2] 59 ff [2] 64 }

  condition:
    any of them
}