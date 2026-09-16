rule TTP_XOR_QUAD_CurrentVersionRun_4bf6 {
  strings:
    $key_4bf6 = { 18 99 [2] 3c 97 [2] 17 bb [2] 39 99 [2] 2d 82 [2] 22 98 [2] 3c 85 [2] 3e 84 [2] 25 82 [2] 39 85 [2] 25 aa }

  condition:
    any of them
}