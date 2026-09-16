rule TTP_XOR_QUAD_CurrentVersionRun_fdd1 {
  strings:
    $key_fdd1 = { ae be [2] 8a b0 [2] a1 9c [2] 8f be [2] 9b a5 [2] 94 bf [2] 8a a2 [2] 88 a3 [2] 93 a5 [2] 8f a2 [2] 93 8d }

  condition:
    any of them
}