rule TTP_XOR_MULT_DOSStub_72ca {
  strings:
    $key_72ca = { 26 a2 [2] 52 ba [2] 15 b8 [2] 52 a9 [2] 1c a5 [2] 10 af [2] 07 a4 [2] 1c ea [2] 21 }

  condition:
    any of them
}