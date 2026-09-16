rule TTP_XOR_QUAD_CurrentVersionRun_60f6 {
  strings:
    $key_60f6 = { 33 99 [2] 17 97 [2] 3c bb [2] 12 99 [2] 06 82 [2] 09 98 [2] 17 85 [2] 15 84 [2] 0e 82 [2] 12 85 [2] 0e aa }

  condition:
    any of them
}