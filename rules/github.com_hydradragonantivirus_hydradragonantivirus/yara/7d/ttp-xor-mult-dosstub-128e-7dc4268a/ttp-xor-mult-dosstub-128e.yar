rule TTP_XOR_MULT_DOSStub_128e {
  strings:
    $key_128e = { 46 e6 [2] 32 fe [2] 75 fc [2] 32 ed [2] 7c e1 [2] 70 eb [2] 67 e0 [2] 7c ae [2] 41 }

  condition:
    any of them
}