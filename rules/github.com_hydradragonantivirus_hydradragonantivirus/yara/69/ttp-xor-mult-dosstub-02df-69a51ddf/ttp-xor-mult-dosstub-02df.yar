rule TTP_XOR_MULT_DOSStub_02df {
  strings:
    $key_02df = { 56 b7 [2] 22 af [2] 65 ad [2] 22 bc [2] 6c b0 [2] 60 ba [2] 77 b1 [2] 6c ff [2] 51 }

  condition:
    any of them
}