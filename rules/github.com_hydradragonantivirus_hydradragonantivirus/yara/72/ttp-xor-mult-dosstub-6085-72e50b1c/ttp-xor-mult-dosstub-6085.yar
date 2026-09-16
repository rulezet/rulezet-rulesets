rule TTP_XOR_MULT_DOSStub_6085 {
  strings:
    $key_6085 = { 34 ed [2] 40 f5 [2] 07 f7 [2] 40 e6 [2] 0e ea [2] 02 e0 [2] 15 eb [2] 0e a5 [2] 33 }

  condition:
    any of them
}