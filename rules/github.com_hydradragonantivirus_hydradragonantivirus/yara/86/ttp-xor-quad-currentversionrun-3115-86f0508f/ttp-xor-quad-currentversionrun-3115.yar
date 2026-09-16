rule TTP_XOR_QUAD_CurrentVersionRun_3115 {
  strings:
    $key_3115 = { 62 7a [2] 46 74 [2] 6d 58 [2] 43 7a [2] 57 61 [2] 58 7b [2] 46 66 [2] 44 67 [2] 5f 61 [2] 43 66 [2] 5f 49 }

  condition:
    any of them
}