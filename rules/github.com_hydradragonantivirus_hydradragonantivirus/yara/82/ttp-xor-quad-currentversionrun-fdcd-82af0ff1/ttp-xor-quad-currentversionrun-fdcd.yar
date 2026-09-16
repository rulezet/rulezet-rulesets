rule TTP_XOR_QUAD_CurrentVersionRun_fdcd {
  strings:
    $key_fdcd = { ae a2 [2] 8a ac [2] a1 80 [2] 8f a2 [2] 9b b9 [2] 94 a3 [2] 8a be [2] 88 bf [2] 93 b9 [2] 8f be [2] 93 91 }

  condition:
    any of them
}