rule TTP_XOR_MULT_DOSStub_e28e {
  strings:
    $key_e28e = { b6 e6 [2] c2 fe [2] 85 fc [2] c2 ed [2] 8c e1 [2] 80 eb [2] 97 e0 [2] 8c ae [2] b1 }

  condition:
    any of them
}