rule TTP_XOR_QUAD_CurrentVersionRun_69f6 {
  strings:
    $key_69f6 = { 3a 99 [2] 1e 97 [2] 35 bb [2] 1b 99 [2] 0f 82 [2] 00 98 [2] 1e 85 [2] 1c 84 [2] 07 82 [2] 1b 85 [2] 07 aa }

  condition:
    any of them
}