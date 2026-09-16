rule TTP_XOR_QUAD_CurrentVersionRun_1f27 {
  strings:
    $key_1f27 = { 4c 48 [2] 68 46 [2] 43 6a [2] 6d 48 [2] 79 53 [2] 76 49 [2] 68 54 [2] 6a 55 [2] 71 53 [2] 6d 54 [2] 71 7b }

  condition:
    any of them
}