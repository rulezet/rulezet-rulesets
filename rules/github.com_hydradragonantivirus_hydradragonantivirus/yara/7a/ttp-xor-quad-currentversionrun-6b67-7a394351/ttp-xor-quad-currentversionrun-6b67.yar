rule TTP_XOR_QUAD_CurrentVersionRun_6b67 {
  strings:
    $key_6b67 = { 38 08 [2] 1c 06 [2] 37 2a [2] 19 08 [2] 0d 13 [2] 02 09 [2] 1c 14 [2] 1e 15 [2] 05 13 [2] 19 14 [2] 05 3b }

  condition:
    any of them
}