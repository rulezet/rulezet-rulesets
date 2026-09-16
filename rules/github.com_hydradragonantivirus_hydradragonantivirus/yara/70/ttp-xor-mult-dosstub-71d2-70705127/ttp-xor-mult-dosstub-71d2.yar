rule TTP_XOR_MULT_DOSStub_71d2 {
  strings:
    $key_71d2 = { 25 ba [2] 51 a2 [2] 16 a0 [2] 51 b1 [2] 1f bd [2] 13 b7 [2] 04 bc [2] 1f f2 [2] 22 }

  condition:
    any of them
}