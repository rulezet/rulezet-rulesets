rule TTP_XOR_QUAD_CurrentVersionRun_78cb {
  strings:
    $key_78cb = { 2b a4 [2] 0f aa [2] 24 86 [2] 0a a4 [2] 1e bf [2] 11 a5 [2] 0f b8 [2] 0d b9 [2] 16 bf [2] 0a b8 [2] 16 97 }

  condition:
    any of them
}