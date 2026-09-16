rule TTP_XOR_MULT_DOSStub_6ed2 {
  strings:
    $key_6ed2 = { 3a ba [2] 4e a2 [2] 09 a0 [2] 4e b1 [2] 00 bd [2] 0c b7 [2] 1b bc [2] 00 f2 [2] 3d }

  condition:
    any of them
}