rule TTP_XOR_QUAD_CurrentVersionRun_0f56 {
  strings:
    $key_0f56 = { 5c 39 [2] 78 37 [2] 53 1b [2] 7d 39 [2] 69 22 [2] 66 38 [2] 78 25 [2] 7a 24 [2] 61 22 [2] 7d 25 [2] 61 0a }

  condition:
    any of them
}