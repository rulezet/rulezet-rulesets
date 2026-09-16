rule TTP_XOR_MULT_DOSStub_af9f {
  strings:
    $key_af9f = { fb f7 [2] 8f ef [2] c8 ed [2] 8f fc [2] c1 f0 [2] cd fa [2] da f1 [2] c1 bf [2] fc }

  condition:
    any of them
}