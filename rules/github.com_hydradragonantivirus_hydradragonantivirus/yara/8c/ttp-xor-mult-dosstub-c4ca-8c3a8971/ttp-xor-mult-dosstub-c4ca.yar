rule TTP_XOR_MULT_DOSStub_c4ca {
  strings:
    $key_c4ca = { 90 a2 [2] e4 ba [2] a3 b8 [2] e4 a9 [2] aa a5 [2] a6 af [2] b1 a4 [2] aa ea [2] 97 }

  condition:
    any of them
}