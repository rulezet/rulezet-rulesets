rule TTP_XOR_MULT_DOSStub_4383 {
  strings:
    $key_4383 = { 17 eb [2] 63 f3 [2] 24 f1 [2] 63 e0 [2] 2d ec [2] 21 e6 [2] 36 ed [2] 2d a3 [2] 10 }

  condition:
    any of them
}