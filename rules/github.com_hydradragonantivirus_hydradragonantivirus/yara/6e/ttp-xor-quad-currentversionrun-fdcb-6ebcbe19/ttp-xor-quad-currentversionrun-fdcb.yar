rule TTP_XOR_QUAD_CurrentVersionRun_fdcb {
  strings:
    $key_fdcb = { ae a4 [2] 8a aa [2] a1 86 [2] 8f a4 [2] 9b bf [2] 94 a5 [2] 8a b8 [2] 88 b9 [2] 93 bf [2] 8f b8 [2] 93 97 }

  condition:
    any of them
}