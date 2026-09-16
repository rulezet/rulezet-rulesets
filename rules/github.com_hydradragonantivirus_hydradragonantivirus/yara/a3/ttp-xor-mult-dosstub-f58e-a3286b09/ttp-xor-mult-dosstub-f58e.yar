rule TTP_XOR_MULT_DOSStub_f58e {
  strings:
    $key_f58e = { a1 e6 [2] d5 fe [2] 92 fc [2] d5 ed [2] 9b e1 [2] 97 eb [2] 80 e0 [2] 9b ae [2] a6 }

  condition:
    any of them
}