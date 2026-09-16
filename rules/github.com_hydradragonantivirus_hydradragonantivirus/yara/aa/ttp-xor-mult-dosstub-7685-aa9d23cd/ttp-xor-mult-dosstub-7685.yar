rule TTP_XOR_MULT_DOSStub_7685 {
  strings:
    $key_7685 = { 22 ed [2] 56 f5 [2] 11 f7 [2] 56 e6 [2] 18 ea [2] 14 e0 [2] 03 eb [2] 18 a5 [2] 25 }

  condition:
    any of them
}