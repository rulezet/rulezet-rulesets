rule TTP_XOR_MULT_DOSStub_358e {
  strings:
    $key_358e = { 61 e6 [2] 15 fe [2] 52 fc [2] 15 ed [2] 5b e1 [2] 57 eb [2] 40 e0 [2] 5b ae [2] 66 }

  condition:
    any of them
}