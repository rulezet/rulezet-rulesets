rule TTP_XOR_QUAD_CurrentVersionRun_0f68 {
  strings:
    $key_0f68 = { 5c 07 [2] 78 09 [2] 53 25 [2] 7d 07 [2] 69 1c [2] 66 06 [2] 78 1b [2] 7a 1a [2] 61 1c [2] 7d 1b [2] 61 34 }

  condition:
    any of them
}