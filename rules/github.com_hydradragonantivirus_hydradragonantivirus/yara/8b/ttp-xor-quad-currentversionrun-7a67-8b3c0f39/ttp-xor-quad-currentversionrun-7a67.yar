rule TTP_XOR_QUAD_CurrentVersionRun_7a67 {
  strings:
    $key_7a67 = { 29 08 [2] 0d 06 [2] 26 2a [2] 08 08 [2] 1c 13 [2] 13 09 [2] 0d 14 [2] 0f 15 [2] 14 13 [2] 08 14 [2] 14 3b }

  condition:
    any of them
}