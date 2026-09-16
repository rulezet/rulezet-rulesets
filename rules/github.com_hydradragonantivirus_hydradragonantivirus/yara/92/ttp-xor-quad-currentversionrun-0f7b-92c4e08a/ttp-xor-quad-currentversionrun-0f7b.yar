rule TTP_XOR_QUAD_CurrentVersionRun_0f7b {
  strings:
    $key_0f7b = { 5c 14 [2] 78 1a [2] 53 36 [2] 7d 14 [2] 69 0f [2] 66 15 [2] 78 08 [2] 7a 09 [2] 61 0f [2] 7d 08 [2] 61 27 }

  condition:
    any of them
}