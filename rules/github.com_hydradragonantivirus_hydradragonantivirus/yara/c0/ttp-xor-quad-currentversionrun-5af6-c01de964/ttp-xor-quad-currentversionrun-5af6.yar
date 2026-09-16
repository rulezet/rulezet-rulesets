rule TTP_XOR_QUAD_CurrentVersionRun_5af6 {
  strings:
    $key_5af6 = { 09 99 [2] 2d 97 [2] 06 bb [2] 28 99 [2] 3c 82 [2] 33 98 [2] 2d 85 [2] 2f 84 [2] 34 82 [2] 28 85 [2] 34 aa }

  condition:
    any of them
}