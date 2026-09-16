rule TTP_XOR_QUAD_CurrentVersionRun_4dcd {
  strings:
    $key_4dcd = { 1e a2 [2] 3a ac [2] 11 80 [2] 3f a2 [2] 2b b9 [2] 24 a3 [2] 3a be [2] 38 bf [2] 23 b9 [2] 3f be [2] 23 91 }

  condition:
    any of them
}