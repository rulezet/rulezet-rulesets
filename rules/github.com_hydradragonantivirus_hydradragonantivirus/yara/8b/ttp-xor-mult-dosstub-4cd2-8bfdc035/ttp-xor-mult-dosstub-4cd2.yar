rule TTP_XOR_MULT_DOSStub_4cd2 {
  strings:
    $key_4cd2 = { 18 ba [2] 6c a2 [2] 2b a0 [2] 6c b1 [2] 22 bd [2] 2e b7 [2] 39 bc [2] 22 f2 [2] 1f }

  condition:
    any of them
}