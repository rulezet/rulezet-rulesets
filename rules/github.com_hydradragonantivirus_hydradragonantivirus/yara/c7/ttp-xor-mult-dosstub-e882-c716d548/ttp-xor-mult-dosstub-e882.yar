rule TTP_XOR_MULT_DOSStub_e882 {
  strings:
    $key_e882 = { bc ea [2] c8 f2 [2] 8f f0 [2] c8 e1 [2] 86 ed [2] 8a e7 [2] 9d ec [2] 86 a2 [2] bb }

  condition:
    any of them
}