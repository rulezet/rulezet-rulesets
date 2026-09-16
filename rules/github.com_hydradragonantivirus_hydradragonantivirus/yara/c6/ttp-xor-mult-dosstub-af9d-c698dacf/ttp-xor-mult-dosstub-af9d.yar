rule TTP_XOR_MULT_DOSStub_af9d {
  strings:
    $key_af9d = { fb f5 [2] 8f ed [2] c8 ef [2] 8f fe [2] c1 f2 [2] cd f8 [2] da f3 [2] c1 bd [2] fc }

  condition:
    any of them
}