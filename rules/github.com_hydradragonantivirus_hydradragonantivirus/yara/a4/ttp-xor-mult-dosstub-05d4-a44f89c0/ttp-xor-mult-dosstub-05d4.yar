rule TTP_XOR_MULT_DOSStub_05d4 {
  strings:
    $key_05d4 = { 51 bc [2] 25 a4 [2] 62 a6 [2] 25 b7 [2] 6b bb [2] 67 b1 [2] 70 ba [2] 6b f4 [2] 56 }

  condition:
    any of them
}