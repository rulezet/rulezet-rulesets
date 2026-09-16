rule TTP_XOR_MULT_DOSStub_a38e {
  strings:
    $key_a38e = { f7 e6 [2] 83 fe [2] c4 fc [2] 83 ed [2] cd e1 [2] c1 eb [2] d6 e0 [2] cd ae [2] f0 }

  condition:
    any of them
}