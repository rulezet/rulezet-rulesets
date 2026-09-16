rule TTP_XOR_QUAD_CurrentVersionRun_7af6 {
  strings:
    $key_7af6 = { 29 99 [2] 0d 97 [2] 26 bb [2] 08 99 [2] 1c 82 [2] 13 98 [2] 0d 85 [2] 0f 84 [2] 14 82 [2] 08 85 [2] 14 aa }

  condition:
    any of them
}