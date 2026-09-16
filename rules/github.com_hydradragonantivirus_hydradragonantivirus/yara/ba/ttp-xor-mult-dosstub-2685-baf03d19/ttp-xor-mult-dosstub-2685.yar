rule TTP_XOR_MULT_DOSStub_2685 {
  strings:
    $key_2685 = { 72 ed [2] 06 f5 [2] 41 f7 [2] 06 e6 [2] 48 ea [2] 44 e0 [2] 53 eb [2] 48 a5 [2] 75 }

  condition:
    any of them
}