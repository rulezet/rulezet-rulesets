rule TTP_XOR_QUAD_CurrentVersionRun_38cb {
  strings:
    $key_38cb = { 6b a4 [2] 4f aa [2] 64 86 [2] 4a a4 [2] 5e bf [2] 51 a5 [2] 4f b8 [2] 4d b9 [2] 56 bf [2] 4a b8 [2] 56 97 }

  condition:
    any of them
}