rule TTP_XOR_MULT_DOSStub_558e {
  strings:
    $key_558e = { 01 e6 [2] 75 fe [2] 32 fc [2] 75 ed [2] 3b e1 [2] 37 eb [2] 20 e0 [2] 3b ae [2] 06 }

  condition:
    any of them
}