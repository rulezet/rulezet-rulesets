rule TTP_XOR_MULT_DOSStub_0ed5 {
  strings:
    $key_0ed5 = { 5a bd [2] 2e a5 [2] 69 a7 [2] 2e b6 [2] 60 ba [2] 6c b0 [2] 7b bb [2] 60 f5 [2] 5d }

  condition:
    any of them
}