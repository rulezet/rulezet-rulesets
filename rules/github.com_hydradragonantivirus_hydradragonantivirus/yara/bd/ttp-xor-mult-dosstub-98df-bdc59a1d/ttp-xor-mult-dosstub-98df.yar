rule TTP_XOR_MULT_DOSStub_98df {
  strings:
    $key_98df = { cc b7 [2] b8 af [2] ff ad [2] b8 bc [2] f6 b0 [2] fa ba [2] ed b1 [2] f6 ff [2] cb }

  condition:
    any of them
}