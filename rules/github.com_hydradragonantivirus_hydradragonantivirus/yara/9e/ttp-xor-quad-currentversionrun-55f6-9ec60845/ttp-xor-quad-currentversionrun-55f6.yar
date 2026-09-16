rule TTP_XOR_QUAD_CurrentVersionRun_55f6 {
  strings:
    $key_55f6 = { 06 99 [2] 22 97 [2] 09 bb [2] 27 99 [2] 33 82 [2] 3c 98 [2] 22 85 [2] 20 84 [2] 3b 82 [2] 27 85 [2] 3b aa }

  condition:
    any of them
}