rule TTP_XOR_QUAD_CurrentVersionRun_48f6 {
  strings:
    $key_48f6 = { 1b 99 [2] 3f 97 [2] 14 bb [2] 3a 99 [2] 2e 82 [2] 21 98 [2] 3f 85 [2] 3d 84 [2] 26 82 [2] 3a 85 [2] 26 aa }

  condition:
    any of them
}