rule TTP_XOR_MULT_DOSStub_0083 {
  strings:
    $key_0083 = { 54 eb [2] 20 f3 [2] 67 f1 [2] 20 e0 [2] 6e ec [2] 62 e6 [2] 75 ed [2] 6e a3 [2] 53 }

  condition:
    any of them
}