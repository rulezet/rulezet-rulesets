rule TTP_XOR_MULT_DOSStub_e58e {
  strings:
    $key_e58e = { b1 e6 [2] c5 fe [2] 82 fc [2] c5 ed [2] 8b e1 [2] 87 eb [2] 90 e0 [2] 8b ae [2] b6 }

  condition:
    any of them
}