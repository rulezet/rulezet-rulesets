rule TTP_XOR_MULT_DOSStub_ed84 {
  strings:
    $key_ed84 = { b9 ec [2] cd f4 [2] 8a f6 [2] cd e7 [2] 83 eb [2] 8f e1 [2] 98 ea [2] 83 a4 [2] be }

  condition:
    any of them
}