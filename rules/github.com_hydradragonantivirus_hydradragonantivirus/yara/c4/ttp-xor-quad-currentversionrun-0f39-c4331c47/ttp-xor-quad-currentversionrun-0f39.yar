rule TTP_XOR_QUAD_CurrentVersionRun_0f39 {
  strings:
    $key_0f39 = { 5c 56 [2] 78 58 [2] 53 74 [2] 7d 56 [2] 69 4d [2] 66 57 [2] 78 4a [2] 7a 4b [2] 61 4d [2] 7d 4a [2] 61 65 }

  condition:
    any of them
}