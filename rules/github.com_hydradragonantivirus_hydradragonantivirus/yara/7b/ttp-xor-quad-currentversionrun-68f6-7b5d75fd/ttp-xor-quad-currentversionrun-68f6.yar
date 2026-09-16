rule TTP_XOR_QUAD_CurrentVersionRun_68f6 {
  strings:
    $key_68f6 = { 3b 99 [2] 1f 97 [2] 34 bb [2] 1a 99 [2] 0e 82 [2] 01 98 [2] 1f 85 [2] 1d 84 [2] 06 82 [2] 1a 85 [2] 06 aa }

  condition:
    any of them
}