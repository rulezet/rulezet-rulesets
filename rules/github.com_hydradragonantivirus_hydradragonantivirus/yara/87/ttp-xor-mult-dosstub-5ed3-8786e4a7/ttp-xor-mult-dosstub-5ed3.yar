rule TTP_XOR_MULT_DOSStub_5ed3 {
  strings:
    $key_5ed3 = { 0a bb [2] 7e a3 [2] 39 a1 [2] 7e b0 [2] 30 bc [2] 3c b6 [2] 2b bd [2] 30 f3 [2] 0d }

  condition:
    any of them
}