rule TTP_XOR_MULT_DOSStub_b78e {
  strings:
    $key_b78e = { e3 e6 [2] 97 fe [2] d0 fc [2] 97 ed [2] d9 e1 [2] d5 eb [2] c2 e0 [2] d9 ae [2] e4 }

  condition:
    any of them
}