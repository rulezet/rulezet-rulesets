rule TTP_XOR_MULT_DOSStub_3ed2 {
  strings:
    $key_3ed2 = { 6a ba [2] 1e a2 [2] 59 a0 [2] 1e b1 [2] 50 bd [2] 5c b7 [2] 4b bc [2] 50 f2 [2] 6d }

  condition:
    any of them
}