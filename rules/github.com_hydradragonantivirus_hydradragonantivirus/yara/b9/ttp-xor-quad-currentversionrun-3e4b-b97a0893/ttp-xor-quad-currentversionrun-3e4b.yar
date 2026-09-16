rule TTP_XOR_QUAD_CurrentVersionRun_3e4b {
  strings:
    $key_3e4b = { 6d 24 [2] 49 2a [2] 62 06 [2] 4c 24 [2] 58 3f [2] 57 25 [2] 49 38 [2] 4b 39 [2] 50 3f [2] 4c 38 [2] 50 17 }

  condition:
    any of them
}