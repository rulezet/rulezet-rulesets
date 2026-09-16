rule TTP_XOR_QUAD_CurrentVersionRun_bf99 {
  strings:
    $key_bf99 = { ec f6 [2] c8 f8 [2] e3 d4 [2] cd f6 [2] d9 ed [2] d6 f7 [2] c8 ea [2] ca eb [2] d1 ed [2] cd ea [2] d1 c5 }

  condition:
    any of them
}