rule TTP_XOR_QUAD_CurrentVersionRun_5067 {
  strings:
    $key_5067 = { 03 08 [2] 27 06 [2] 0c 2a [2] 22 08 [2] 36 13 [2] 39 09 [2] 27 14 [2] 25 15 [2] 3e 13 [2] 22 14 [2] 3e 3b }

  condition:
    any of them
}