rule TTP_XOR_MULT_DOSStub_2ed2 {
  strings:
    $key_2ed2 = { 7a ba [2] 0e a2 [2] 49 a0 [2] 0e b1 [2] 40 bd [2] 4c b7 [2] 5b bc [2] 40 f2 [2] 7d }

  condition:
    any of them
}