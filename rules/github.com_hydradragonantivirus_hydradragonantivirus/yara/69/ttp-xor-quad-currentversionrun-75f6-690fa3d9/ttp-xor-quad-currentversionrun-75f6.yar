rule TTP_XOR_QUAD_CurrentVersionRun_75f6 {
  strings:
    $key_75f6 = { 26 99 [2] 02 97 [2] 29 bb [2] 07 99 [2] 13 82 [2] 1c 98 [2] 02 85 [2] 00 84 [2] 1b 82 [2] 07 85 [2] 1b aa }

  condition:
    any of them
}