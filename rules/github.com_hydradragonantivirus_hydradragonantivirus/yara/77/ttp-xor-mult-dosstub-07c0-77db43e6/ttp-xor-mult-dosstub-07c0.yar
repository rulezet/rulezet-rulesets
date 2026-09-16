rule TTP_XOR_MULT_DOSStub_07c0 {
  strings:
    $key_07c0 = { 53 a8 [2] 27 b0 [2] 60 b2 [2] 27 a3 [2] 69 af [2] 65 a5 [2] 72 ae [2] 69 e0 [2] 54 }

  condition:
    any of them
}