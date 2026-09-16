rule TTP_XOR_MULT_DOSStub_af85 {
  strings:
    $key_af85 = { fb ed [2] 8f f5 [2] c8 f7 [2] 8f e6 [2] c1 ea [2] cd e0 [2] da eb [2] c1 a5 [2] fc }

  condition:
    any of them
}