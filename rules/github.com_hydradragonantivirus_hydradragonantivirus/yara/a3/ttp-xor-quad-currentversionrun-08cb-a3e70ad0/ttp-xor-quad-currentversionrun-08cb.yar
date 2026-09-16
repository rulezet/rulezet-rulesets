rule TTP_XOR_QUAD_CurrentVersionRun_08cb {
  strings:
    $key_08cb = { 5b a4 [2] 7f aa [2] 54 86 [2] 7a a4 [2] 6e bf [2] 61 a5 [2] 7f b8 [2] 7d b9 [2] 66 bf [2] 7a b8 [2] 66 97 }

  condition:
    any of them
}