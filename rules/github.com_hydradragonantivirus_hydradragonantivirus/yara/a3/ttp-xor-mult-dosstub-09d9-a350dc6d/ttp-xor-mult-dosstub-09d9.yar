rule TTP_XOR_MULT_DOSStub_09d9 {
  strings:
    $key_09d9 = { 5d b1 [2] 29 a9 [2] 6e ab [2] 29 ba [2] 67 b6 [2] 6b bc [2] 7c b7 [2] 67 f9 [2] 5a }

  condition:
    any of them
}