rule TTP_XOR_MULT_DOSStub_65d9 {
  strings:
    $key_65d9 = { 31 b1 [2] 45 a9 [2] 02 ab [2] 45 ba [2] 0b b6 [2] 07 bc [2] 10 b7 [2] 0b f9 [2] 36 }

  condition:
    any of them
}