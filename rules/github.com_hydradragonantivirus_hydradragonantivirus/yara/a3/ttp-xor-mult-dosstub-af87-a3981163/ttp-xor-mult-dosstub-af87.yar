rule TTP_XOR_MULT_DOSStub_af87 {
  strings:
    $key_af87 = { fb ef [2] 8f f7 [2] c8 f5 [2] 8f e4 [2] c1 e8 [2] cd e2 [2] da e9 [2] c1 a7 [2] fc }

  condition:
    any of them
}