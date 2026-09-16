rule TTP_XOR_MULT_DOSStub_e785 {
  strings:
    $key_e785 = { b3 ed [2] c7 f5 [2] 80 f7 [2] c7 e6 [2] 89 ea [2] 85 e0 [2] 92 eb [2] 89 a5 [2] b4 }

  condition:
    any of them
}