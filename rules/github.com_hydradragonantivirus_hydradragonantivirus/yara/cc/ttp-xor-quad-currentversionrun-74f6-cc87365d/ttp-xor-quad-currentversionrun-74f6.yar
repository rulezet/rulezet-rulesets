rule TTP_XOR_QUAD_CurrentVersionRun_74f6 {
  strings:
    $key_74f6 = { 27 99 [2] 03 97 [2] 28 bb [2] 06 99 [2] 12 82 [2] 1d 98 [2] 03 85 [2] 01 84 [2] 1a 82 [2] 06 85 [2] 1a aa }

  condition:
    any of them
}