rule TTP_XOR_QUAD_CurrentVersionRun_7df6 {
  strings:
    $key_7df6 = { 2e 99 [2] 0a 97 [2] 21 bb [2] 0f 99 [2] 1b 82 [2] 14 98 [2] 0a 85 [2] 08 84 [2] 13 82 [2] 0f 85 [2] 13 aa }

  condition:
    any of them
}