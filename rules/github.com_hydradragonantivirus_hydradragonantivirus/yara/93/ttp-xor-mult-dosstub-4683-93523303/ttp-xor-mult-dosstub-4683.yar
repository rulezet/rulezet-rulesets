rule TTP_XOR_MULT_DOSStub_4683 {
  strings:
    $key_4683 = { 12 eb [2] 66 f3 [2] 21 f1 [2] 66 e0 [2] 28 ec [2] 24 e6 [2] 33 ed [2] 28 a3 [2] 15 }

  condition:
    any of them
}