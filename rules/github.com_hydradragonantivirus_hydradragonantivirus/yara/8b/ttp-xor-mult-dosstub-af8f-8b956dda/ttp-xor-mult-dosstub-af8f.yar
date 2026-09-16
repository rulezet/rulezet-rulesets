rule TTP_XOR_MULT_DOSStub_af8f {
  strings:
    $key_af8f = { fb e7 [2] 8f ff [2] c8 fd [2] 8f ec [2] c1 e0 [2] cd ea [2] da e1 [2] c1 af [2] fc }

  condition:
    any of them
}