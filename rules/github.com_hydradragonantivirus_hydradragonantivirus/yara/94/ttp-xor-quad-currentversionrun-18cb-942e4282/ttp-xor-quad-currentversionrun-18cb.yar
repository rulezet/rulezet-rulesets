rule TTP_XOR_QUAD_CurrentVersionRun_18cb {
  strings:
    $key_18cb = { 4b a4 [2] 6f aa [2] 44 86 [2] 6a a4 [2] 7e bf [2] 71 a5 [2] 6f b8 [2] 6d b9 [2] 76 bf [2] 6a b8 [2] 76 97 }

  condition:
    any of them
}