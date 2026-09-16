rule TTP_XOR_MULT_DOSStub_2683 {
  strings:
    $key_2683 = { 72 eb [2] 06 f3 [2] 41 f1 [2] 06 e0 [2] 48 ec [2] 44 e6 [2] 53 ed [2] 48 a3 [2] 75 }

  condition:
    any of them
}