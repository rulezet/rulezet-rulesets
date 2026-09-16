rule TTP_XOR_MULT_DOSStub_d9df {
  strings:
    $key_d9df = { 8d b7 [2] f9 af [2] be ad [2] f9 bc [2] b7 b0 [2] bb ba [2] ac b1 [2] b7 ff [2] 8a }

  condition:
    any of them
}