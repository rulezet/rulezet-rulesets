rule TTP_XOR_MULT_DOSStub_1ed5 {
  strings:
    $key_1ed5 = { 4a bd [2] 3e a5 [2] 79 a7 [2] 3e b6 [2] 70 ba [2] 7c b0 [2] 6b bb [2] 70 f5 [2] 4d }

  condition:
    any of them
}