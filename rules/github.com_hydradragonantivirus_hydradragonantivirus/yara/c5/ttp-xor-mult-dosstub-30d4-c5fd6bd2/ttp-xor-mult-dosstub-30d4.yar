rule TTP_XOR_MULT_DOSStub_30d4 {
  strings:
    $key_30d4 = { 64 bc [2] 10 a4 [2] 57 a6 [2] 10 b7 [2] 5e bb [2] 52 b1 [2] 45 ba [2] 5e f4 [2] 63 }

  condition:
    any of them
}