rule TTP_XOR_MULT_DOSStub_4ed3 {
  strings:
    $key_4ed3 = { 1a bb [2] 6e a3 [2] 29 a1 [2] 6e b0 [2] 20 bc [2] 2c b6 [2] 3b bd [2] 20 f3 [2] 1d }

  condition:
    any of them
}