rule TTP_XOR_MULT_DOSStub_b68e {
  strings:
    $key_b68e = { e2 e6 [2] 96 fe [2] d1 fc [2] 96 ed [2] d8 e1 [2] d4 eb [2] c3 e0 [2] d8 ae [2] e5 }

  condition:
    any of them
}