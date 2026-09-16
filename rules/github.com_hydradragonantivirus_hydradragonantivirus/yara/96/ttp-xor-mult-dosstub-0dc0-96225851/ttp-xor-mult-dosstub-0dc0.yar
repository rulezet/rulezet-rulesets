rule TTP_XOR_MULT_DOSStub_0dc0 {
  strings:
    $key_0dc0 = { 59 a8 [2] 2d b0 [2] 6a b2 [2] 2d a3 [2] 63 af [2] 6f a5 [2] 78 ae [2] 63 e0 [2] 5e }

  condition:
    any of them
}