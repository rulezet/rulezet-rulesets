rule TTP_XOR_QUAD_CurrentVersionRun_0f75 {
  strings:
    $key_0f75 = { 5c 1a [2] 78 14 [2] 53 38 [2] 7d 1a [2] 69 01 [2] 66 1b [2] 78 06 [2] 7a 07 [2] 61 01 [2] 7d 06 [2] 61 29 }

  condition:
    any of them
}