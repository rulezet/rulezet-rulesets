rule TTP_XOR_MULT_DOSStub_24df {
  strings:
    $key_24df = { 70 b7 [2] 04 af [2] 43 ad [2] 04 bc [2] 4a b0 [2] 46 ba [2] 51 b1 [2] 4a ff [2] 77 }

  condition:
    any of them
}