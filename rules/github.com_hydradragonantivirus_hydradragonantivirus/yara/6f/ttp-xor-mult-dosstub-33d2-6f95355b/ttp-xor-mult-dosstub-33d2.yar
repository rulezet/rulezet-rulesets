rule TTP_XOR_MULT_DOSStub_33d2 {
  strings:
    $key_33d2 = { 67 ba [2] 13 a2 [2] 54 a0 [2] 13 b1 [2] 5d bd [2] 51 b7 [2] 46 bc [2] 5d f2 [2] 60 }

  condition:
    any of them
}