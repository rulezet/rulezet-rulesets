rule TTP_XOR_MULT_DOSStub_71c0 {
  strings:
    $key_71c0 = { 25 a8 [2] 51 b0 [2] 16 b2 [2] 51 a3 [2] 1f af [2] 13 a5 [2] 04 ae [2] 1f e0 [2] 22 }

  condition:
    any of them
}