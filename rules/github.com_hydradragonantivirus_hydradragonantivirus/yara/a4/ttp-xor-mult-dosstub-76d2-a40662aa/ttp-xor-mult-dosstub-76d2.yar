rule TTP_XOR_MULT_DOSStub_76d2 {
  strings:
    $key_76d2 = { 22 ba [2] 56 a2 [2] 11 a0 [2] 56 b1 [2] 18 bd [2] 14 b7 [2] 03 bc [2] 18 f2 [2] 25 }

  condition:
    any of them
}