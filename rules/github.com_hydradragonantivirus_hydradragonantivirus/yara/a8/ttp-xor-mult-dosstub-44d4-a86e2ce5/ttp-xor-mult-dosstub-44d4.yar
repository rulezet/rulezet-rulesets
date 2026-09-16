rule TTP_XOR_MULT_DOSStub_44d4 {
  strings:
    $key_44d4 = { 10 bc [2] 64 a4 [2] 23 a6 [2] 64 b7 [2] 2a bb [2] 26 b1 [2] 31 ba [2] 2a f4 [2] 17 }

  condition:
    any of them
}