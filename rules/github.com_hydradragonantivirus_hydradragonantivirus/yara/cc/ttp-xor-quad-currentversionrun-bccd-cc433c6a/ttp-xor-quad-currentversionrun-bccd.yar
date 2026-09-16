rule TTP_XOR_QUAD_CurrentVersionRun_bccd {
  strings:
    $key_bccd = { ef a2 [2] cb ac [2] e0 80 [2] ce a2 [2] da b9 [2] d5 a3 [2] cb be [2] c9 bf [2] d2 b9 [2] ce be [2] d2 91 }

  condition:
    any of them
}