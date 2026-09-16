rule TTP_XOR_QUAD_CurrentVersionRun_6027 {
  strings:
    $key_6027 = { 33 48 [2] 17 46 [2] 3c 6a [2] 12 48 [2] 06 53 [2] 09 49 [2] 17 54 [2] 15 55 [2] 0e 53 [2] 12 54 [2] 0e 7b }

  condition:
    any of them
}