rule TTP_XOR_QUAD_CurrentVersionRun_1727 {
  strings:
    $key_1727 = { 44 48 [2] 60 46 [2] 4b 6a [2] 65 48 [2] 71 53 [2] 7e 49 [2] 60 54 [2] 62 55 [2] 79 53 [2] 65 54 [2] 79 7b }

  condition:
    any of them
}