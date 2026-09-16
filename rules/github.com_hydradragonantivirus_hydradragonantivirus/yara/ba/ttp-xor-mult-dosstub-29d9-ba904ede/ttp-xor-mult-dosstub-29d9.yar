rule TTP_XOR_MULT_DOSStub_29d9 {
  strings:
    $key_29d9 = { 7d b1 [2] 09 a9 [2] 4e ab [2] 09 ba [2] 47 b6 [2] 4b bc [2] 5c b7 [2] 47 f9 [2] 7a }

  condition:
    any of them
}