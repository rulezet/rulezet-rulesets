rule TTP_XOR_MULT_DOSStub_158e {
  strings:
    $key_158e = { 41 e6 [2] 35 fe [2] 72 fc [2] 35 ed [2] 7b e1 [2] 77 eb [2] 60 e0 [2] 7b ae [2] 46 }

  condition:
    any of them
}