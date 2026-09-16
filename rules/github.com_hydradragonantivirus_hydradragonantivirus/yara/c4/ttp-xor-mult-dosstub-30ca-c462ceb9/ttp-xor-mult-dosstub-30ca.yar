rule TTP_XOR_MULT_DOSStub_30ca {
  strings:
    $key_30ca = { 64 a2 [2] 10 ba [2] 57 b8 [2] 10 a9 [2] 5e a5 [2] 52 af [2] 45 a4 [2] 5e ea [2] 63 }

  condition:
    any of them
}