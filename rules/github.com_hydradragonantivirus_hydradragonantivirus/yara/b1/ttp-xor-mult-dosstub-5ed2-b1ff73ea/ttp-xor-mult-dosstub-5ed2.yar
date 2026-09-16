rule TTP_XOR_MULT_DOSStub_5ed2 {
  strings:
    $key_5ed2 = { 0a ba [2] 7e a2 [2] 39 a0 [2] 7e b1 [2] 30 bd [2] 3c b7 [2] 2b bc [2] 30 f2 [2] 0d }

  condition:
    any of them
}