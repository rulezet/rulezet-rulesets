rule TTP_XOR_MULT_DOSStub_a58e {
  strings:
    $key_a58e = { f1 e6 [2] 85 fe [2] c2 fc [2] 85 ed [2] cb e1 [2] c7 eb [2] d0 e0 [2] cb ae [2] f6 }

  condition:
    any of them
}