rule TTP_XOR_QUAD_CurrentVersionRun_25f6 {
  strings:
    $key_25f6 = { 76 99 [2] 52 97 [2] 79 bb [2] 57 99 [2] 43 82 [2] 4c 98 [2] 52 85 [2] 50 84 [2] 4b 82 [2] 57 85 [2] 4b aa }

  condition:
    any of them
}