rule TTP_XOR_MULT_DOSStub_3882 {
  strings:
    $key_3882 = { 6c ea [2] 18 f2 [2] 5f f0 [2] 18 e1 [2] 56 ed [2] 5a e7 [2] 4d ec [2] 56 a2 [2] 6b }

  condition:
    any of them
}