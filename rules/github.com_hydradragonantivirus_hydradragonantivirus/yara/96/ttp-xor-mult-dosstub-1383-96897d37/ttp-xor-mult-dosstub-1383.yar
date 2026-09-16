rule TTP_XOR_MULT_DOSStub_1383 {
  strings:
    $key_1383 = { 47 eb [2] 33 f3 [2] 74 f1 [2] 33 e0 [2] 7d ec [2] 71 e6 [2] 66 ed [2] 7d a3 [2] 40 }

  condition:
    any of them
}