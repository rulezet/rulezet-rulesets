rule TTP_XOR_QUAD_CurrentVersionRun_6df6 {
  strings:
    $key_6df6 = { 3e 99 [2] 1a 97 [2] 31 bb [2] 1f 99 [2] 0b 82 [2] 04 98 [2] 1a 85 [2] 18 84 [2] 03 82 [2] 1f 85 [2] 03 aa }

  condition:
    any of them
}