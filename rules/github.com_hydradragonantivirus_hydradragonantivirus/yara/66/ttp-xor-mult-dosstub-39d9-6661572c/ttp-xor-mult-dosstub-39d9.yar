rule TTP_XOR_MULT_DOSStub_39d9 {
  strings:
    $key_39d9 = { 6d b1 [2] 19 a9 [2] 5e ab [2] 19 ba [2] 57 b6 [2] 5b bc [2] 4c b7 [2] 57 f9 [2] 6a }

  condition:
    any of them
}