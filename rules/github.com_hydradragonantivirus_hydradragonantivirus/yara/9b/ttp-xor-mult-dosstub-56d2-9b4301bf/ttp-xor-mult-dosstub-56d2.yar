rule TTP_XOR_MULT_DOSStub_56d2 {
  strings:
    $key_56d2 = { 02 ba [2] 76 a2 [2] 31 a0 [2] 76 b1 [2] 38 bd [2] 34 b7 [2] 23 bc [2] 38 f2 [2] 05 }

  condition:
    any of them
}