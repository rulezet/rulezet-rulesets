rule TTP_XOR_MULT_DOSStub_ed9c {
  strings:
    $key_ed9c = { b9 f4 [2] cd ec [2] 8a ee [2] cd ff [2] 83 f3 [2] 8f f9 [2] 98 f2 [2] 83 bc [2] be }

  condition:
    any of them
}