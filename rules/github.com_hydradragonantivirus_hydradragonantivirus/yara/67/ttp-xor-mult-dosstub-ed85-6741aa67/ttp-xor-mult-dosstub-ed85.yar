rule TTP_XOR_MULT_DOSStub_ed85 {
  strings:
    $key_ed85 = { b9 ed [2] cd f5 [2] 8a f7 [2] cd e6 [2] 83 ea [2] 8f e0 [2] 98 eb [2] 83 a5 [2] be }

  condition:
    any of them
}