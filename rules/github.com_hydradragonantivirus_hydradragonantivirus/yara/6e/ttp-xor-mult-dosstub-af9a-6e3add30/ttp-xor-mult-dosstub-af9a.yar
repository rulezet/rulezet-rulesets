rule TTP_XOR_MULT_DOSStub_af9a {
  strings:
    $key_af9a = { fb f2 [2] 8f ea [2] c8 e8 [2] 8f f9 [2] c1 f5 [2] cd ff [2] da f4 [2] c1 ba [2] fc }

  condition:
    any of them
}