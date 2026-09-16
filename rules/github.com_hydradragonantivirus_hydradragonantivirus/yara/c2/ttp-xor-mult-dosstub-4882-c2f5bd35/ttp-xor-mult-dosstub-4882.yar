rule TTP_XOR_MULT_DOSStub_4882 {
  strings:
    $key_4882 = { 1c ea [2] 68 f2 [2] 2f f0 [2] 68 e1 [2] 26 ed [2] 2a e7 [2] 3d ec [2] 26 a2 [2] 1b }

  condition:
    any of them
}