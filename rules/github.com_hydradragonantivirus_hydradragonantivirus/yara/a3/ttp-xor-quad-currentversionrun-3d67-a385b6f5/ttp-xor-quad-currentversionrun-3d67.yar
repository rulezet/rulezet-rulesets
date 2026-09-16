rule TTP_XOR_QUAD_CurrentVersionRun_3d67 {
  strings:
    $key_3d67 = { 6e 08 [2] 4a 06 [2] 61 2a [2] 4f 08 [2] 5b 13 [2] 54 09 [2] 4a 14 [2] 48 15 [2] 53 13 [2] 4f 14 [2] 53 3b }

  condition:
    any of them
}