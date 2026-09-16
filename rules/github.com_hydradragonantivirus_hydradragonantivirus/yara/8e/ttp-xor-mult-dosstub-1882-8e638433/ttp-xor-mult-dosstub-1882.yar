rule TTP_XOR_MULT_DOSStub_1882 {
  strings:
    $key_1882 = { 4c ea [2] 38 f2 [2] 7f f0 [2] 38 e1 [2] 76 ed [2] 7a e7 [2] 6d ec [2] 76 a2 [2] 4b }

  condition:
    any of them
}