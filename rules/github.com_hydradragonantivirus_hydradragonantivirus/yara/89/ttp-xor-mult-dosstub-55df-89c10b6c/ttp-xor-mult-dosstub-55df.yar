rule TTP_XOR_MULT_DOSStub_55df {
  strings:
    $key_55df = { 01 b7 [2] 75 af [2] 32 ad [2] 75 bc [2] 3b b0 [2] 37 ba [2] 20 b1 [2] 3b ff [2] 06 }

  condition:
    any of them
}