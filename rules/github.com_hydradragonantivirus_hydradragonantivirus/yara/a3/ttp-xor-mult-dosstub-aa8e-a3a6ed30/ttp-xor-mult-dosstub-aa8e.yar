rule TTP_XOR_MULT_DOSStub_aa8e {
  strings:
    $key_aa8e = { fe e6 [2] 8a fe [2] cd fc [2] 8a ed [2] c4 e1 [2] c8 eb [2] df e0 [2] c4 ae [2] f9 }

  condition:
    any of them
}