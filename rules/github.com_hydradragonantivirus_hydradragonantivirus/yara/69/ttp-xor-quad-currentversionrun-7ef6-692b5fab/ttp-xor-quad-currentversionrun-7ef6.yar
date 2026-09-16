rule TTP_XOR_QUAD_CurrentVersionRun_7ef6 {
  strings:
    $key_7ef6 = { 2d 99 [2] 09 97 [2] 22 bb [2] 0c 99 [2] 18 82 [2] 17 98 [2] 09 85 [2] 0b 84 [2] 10 82 [2] 0c 85 [2] 10 aa }

  condition:
    any of them
}