rule TTP_XOR_QUAD_CurrentVersionRun_6a67 {
  strings:
    $key_6a67 = { 39 08 [2] 1d 06 [2] 36 2a [2] 18 08 [2] 0c 13 [2] 03 09 [2] 1d 14 [2] 1f 15 [2] 04 13 [2] 18 14 [2] 04 3b }

  condition:
    any of them
}