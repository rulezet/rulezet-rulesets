rule TTP_XOR_MULT_DOSStub_ed8d {
  strings:
    $key_ed8d = { b9 e5 [2] cd fd [2] 8a ff [2] cd ee [2] 83 e2 [2] 8f e8 [2] 98 e3 [2] 83 ad [2] be }

  condition:
    any of them
}