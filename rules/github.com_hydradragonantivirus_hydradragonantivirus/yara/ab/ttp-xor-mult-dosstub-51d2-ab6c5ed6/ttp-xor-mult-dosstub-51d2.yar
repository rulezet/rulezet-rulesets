rule TTP_XOR_MULT_DOSStub_51d2 {
  strings:
    $key_51d2 = { 05 ba [2] 71 a2 [2] 36 a0 [2] 71 b1 [2] 3f bd [2] 33 b7 [2] 24 bc [2] 3f f2 [2] 02 }

  condition:
    any of them
}