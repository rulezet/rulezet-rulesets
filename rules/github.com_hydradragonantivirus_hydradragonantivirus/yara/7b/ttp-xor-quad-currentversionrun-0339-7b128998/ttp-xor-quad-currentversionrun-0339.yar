rule TTP_XOR_QUAD_CurrentVersionRun_0339 {
  strings:
    $key_0339 = { 50 56 [2] 74 58 [2] 5f 74 [2] 71 56 [2] 65 4d [2] 6a 57 [2] 74 4a [2] 76 4b [2] 6d 4d [2] 71 4a [2] 6d 65 }

  condition:
    any of them
}