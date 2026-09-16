rule TTP_XOR_MULT_DOSStub_23c0 {
  strings:
    $key_23c0 = { 77 a8 [2] 03 b0 [2] 44 b2 [2] 03 a3 [2] 4d af [2] 41 a5 [2] 56 ae [2] 4d e0 [2] 70 }

  condition:
    any of them
}