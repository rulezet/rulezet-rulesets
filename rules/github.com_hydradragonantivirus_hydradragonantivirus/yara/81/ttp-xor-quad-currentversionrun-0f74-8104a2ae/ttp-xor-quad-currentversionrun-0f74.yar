rule TTP_XOR_QUAD_CurrentVersionRun_0f74 {
  strings:
    $key_0f74 = { 5c 1b [2] 78 15 [2] 53 39 [2] 7d 1b [2] 69 00 [2] 66 1a [2] 78 07 [2] 7a 06 [2] 61 00 [2] 7d 07 [2] 61 28 }

  condition:
    any of them
}