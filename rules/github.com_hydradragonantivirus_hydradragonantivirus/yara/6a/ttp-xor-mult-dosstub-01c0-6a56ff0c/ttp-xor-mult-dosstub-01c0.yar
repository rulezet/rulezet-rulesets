rule TTP_XOR_MULT_DOSStub_01c0 {
  strings:
    $key_01c0 = { 55 a8 [2] 21 b0 [2] 66 b2 [2] 21 a3 [2] 6f af [2] 63 a5 [2] 74 ae [2] 6f e0 [2] 52 }

  condition:
    any of them
}