rule TTP_XOR_MULT_DOSStub_d996 {
  strings:
    $key_d996 = { 8d fe [2] f9 e6 [2] be e4 [2] f9 f5 [2] b7 f9 [2] bb f3 [2] ac f8 [2] b7 b6 [2] 8a }

  condition:
    any of them
}