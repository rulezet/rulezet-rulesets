rule TTP_XOR_MULT_DOSStub_afcc {
  strings:
    $key_afcc = { fb a4 [2] 8f bc [2] c8 be [2] 8f af [2] c1 a3 [2] cd a9 [2] da a2 [2] c1 ec [2] fc }

  condition:
    any of them
}