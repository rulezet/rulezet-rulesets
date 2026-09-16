rule TTP_XOR_QUAD_CurrentVersionRun_0f4b {
  strings:
    $key_0f4b = { 5c 24 [2] 78 2a [2] 53 06 [2] 7d 24 [2] 69 3f [2] 66 25 [2] 78 38 [2] 7a 39 [2] 61 3f [2] 7d 38 [2] 61 17 }

  condition:
    any of them
}