rule TTP_XOR_MULT_DOSStub_b18e {
  strings:
    $key_b18e = { e5 e6 [2] 91 fe [2] d6 fc [2] 91 ed [2] df e1 [2] d3 eb [2] c4 e0 [2] df ae [2] e2 }

  condition:
    any of them
}