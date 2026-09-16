rule TTP_XOR_MULT_DOSStub_3ed3 {
  strings:
    $key_3ed3 = { 6a bb [2] 1e a3 [2] 59 a1 [2] 1e b0 [2] 50 bc [2] 5c b6 [2] 4b bd [2] 50 f3 [2] 6d }

  condition:
    any of them
}