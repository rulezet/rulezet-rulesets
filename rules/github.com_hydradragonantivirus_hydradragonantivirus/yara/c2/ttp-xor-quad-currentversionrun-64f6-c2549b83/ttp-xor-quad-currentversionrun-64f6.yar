rule TTP_XOR_QUAD_CurrentVersionRun_64f6 {
  strings:
    $key_64f6 = { 37 99 [2] 13 97 [2] 38 bb [2] 16 99 [2] 02 82 [2] 0d 98 [2] 13 85 [2] 11 84 [2] 0a 82 [2] 16 85 [2] 0a aa }

  condition:
    any of them
}