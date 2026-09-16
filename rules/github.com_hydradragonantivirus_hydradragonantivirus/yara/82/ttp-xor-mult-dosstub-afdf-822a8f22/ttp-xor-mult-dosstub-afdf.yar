rule TTP_XOR_MULT_DOSStub_afdf {
  strings:
    $key_afdf = { fb b7 [2] 8f af [2] c8 ad [2] 8f bc [2] c1 b0 [2] cd ba [2] da b1 [2] c1 ff [2] fc }

  condition:
    any of them
}