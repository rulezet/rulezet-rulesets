rule TTP_XOR_MULT_DOSStub_7683 {
  strings:
    $key_7683 = { 22 eb [2] 56 f3 [2] 11 f1 [2] 56 e0 [2] 18 ec [2] 14 e6 [2] 03 ed [2] 18 a3 [2] 25 }

  condition:
    any of them
}