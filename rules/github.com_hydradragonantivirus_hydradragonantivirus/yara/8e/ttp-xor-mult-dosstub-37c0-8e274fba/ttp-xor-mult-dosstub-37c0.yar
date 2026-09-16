rule TTP_XOR_MULT_DOSStub_37c0 {
  strings:
    $key_37c0 = { 63 a8 [2] 17 b0 [2] 50 b2 [2] 17 a3 [2] 59 af [2] 55 a5 [2] 42 ae [2] 59 e0 [2] 64 }

  condition:
    any of them
}