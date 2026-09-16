rule TTP_XOR_MULT_DOSStub_7ed3 {
  strings:
    $key_7ed3 = { 2a bb [2] 5e a3 [2] 19 a1 [2] 5e b0 [2] 10 bc [2] 1c b6 [2] 0b bd [2] 10 f3 [2] 2d }

  condition:
    any of them
}