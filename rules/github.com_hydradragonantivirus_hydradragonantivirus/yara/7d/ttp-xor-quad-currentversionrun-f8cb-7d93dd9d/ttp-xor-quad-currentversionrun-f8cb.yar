rule TTP_XOR_QUAD_CurrentVersionRun_f8cb {
  strings:
    $key_f8cb = { ab a4 [2] 8f aa [2] a4 86 [2] 8a a4 [2] 9e bf [2] 91 a5 [2] 8f b8 [2] 8d b9 [2] 96 bf [2] 8a b8 [2] 96 97 }

  condition:
    any of them
}