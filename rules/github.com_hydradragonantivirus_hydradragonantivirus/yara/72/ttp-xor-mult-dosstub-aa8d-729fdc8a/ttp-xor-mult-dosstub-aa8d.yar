rule TTP_XOR_MULT_DOSStub_aa8d {
  strings:
    $key_aa8d = { fe e5 [2] 8a fd [2] cd ff [2] 8a ee [2] c4 e2 [2] c8 e8 [2] df e3 [2] c4 ad [2] f9 }

  condition:
    any of them
}