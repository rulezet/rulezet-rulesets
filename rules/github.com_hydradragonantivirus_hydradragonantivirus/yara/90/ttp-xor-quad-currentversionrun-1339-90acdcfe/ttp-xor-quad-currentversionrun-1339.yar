rule TTP_XOR_QUAD_CurrentVersionRun_1339 {
  strings:
    $key_1339 = { 40 56 [2] 64 58 [2] 4f 74 [2] 61 56 [2] 75 4d [2] 7a 57 [2] 64 4a [2] 66 4b [2] 7d 4d [2] 61 4a [2] 7d 65 }

  condition:
    any of them
}