rule TTP_XOR_MULT_DOSStub_1ed2 {
  strings:
    $key_1ed2 = { 4a ba [2] 3e a2 [2] 79 a0 [2] 3e b1 [2] 70 bd [2] 7c b7 [2] 6b bc [2] 70 f2 [2] 4d }

  condition:
    any of them
}