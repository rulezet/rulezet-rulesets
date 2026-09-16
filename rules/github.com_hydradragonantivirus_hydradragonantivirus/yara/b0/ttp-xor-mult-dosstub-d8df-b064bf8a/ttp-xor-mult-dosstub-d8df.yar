rule TTP_XOR_MULT_DOSStub_d8df {
  strings:
    $key_d8df = { 8c b7 [2] f8 af [2] bf ad [2] f8 bc [2] b6 b0 [2] ba ba [2] ad b1 [2] b6 ff [2] 8b }

  condition:
    any of them
}