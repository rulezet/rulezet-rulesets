rule TTP_XOR_MULT_DOSStub_30d9 {
  strings:
    $key_30d9 = { 64 b1 [2] 10 a9 [2] 57 ab [2] 10 ba [2] 5e b6 [2] 52 bc [2] 45 b7 [2] 5e f9 [2] 63 }

  condition:
    any of them
}