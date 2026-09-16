rule TTP_XOR_MULT_DOSStub_36df {
  strings:
    $key_36df = { 62 b7 [2] 16 af [2] 51 ad [2] 16 bc [2] 58 b0 [2] 54 ba [2] 43 b1 [2] 58 ff [2] 65 }

  condition:
    any of them
}