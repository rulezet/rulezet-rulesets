rule TTP_XOR_MULT_DOSStub_edcc {
  strings:
    $key_edcc = { b9 a4 [2] cd bc [2] 8a be [2] cd af [2] 83 a3 [2] 8f a9 [2] 98 a2 [2] 83 ec [2] be }

  condition:
    any of them
}