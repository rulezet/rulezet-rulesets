rule TTP_XOR_MULT_DOSStub_af91 {
  strings:
    $key_af91 = { fb f9 [2] 8f e1 [2] c8 e3 [2] 8f f2 [2] c1 fe [2] cd f4 [2] da ff [2] c1 b1 [2] fc }

  condition:
    any of them
}