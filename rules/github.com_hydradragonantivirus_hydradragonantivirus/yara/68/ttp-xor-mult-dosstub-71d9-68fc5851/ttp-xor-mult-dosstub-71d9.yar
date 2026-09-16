rule TTP_XOR_MULT_DOSStub_71d9 {
  strings:
    $key_71d9 = { 25 b1 [2] 51 a9 [2] 16 ab [2] 51 ba [2] 1f b6 [2] 13 bc [2] 04 b7 [2] 1f f9 [2] 22 }

  condition:
    any of them
}