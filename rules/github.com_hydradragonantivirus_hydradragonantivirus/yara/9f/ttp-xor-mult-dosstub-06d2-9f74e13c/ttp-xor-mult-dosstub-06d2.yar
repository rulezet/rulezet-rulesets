rule TTP_XOR_MULT_DOSStub_06d2 {
  strings:
    $key_06d2 = { 52 ba [2] 26 a2 [2] 61 a0 [2] 26 b1 [2] 68 bd [2] 64 b7 [2] 73 bc [2] 68 f2 [2] 55 }

  condition:
    any of them
}