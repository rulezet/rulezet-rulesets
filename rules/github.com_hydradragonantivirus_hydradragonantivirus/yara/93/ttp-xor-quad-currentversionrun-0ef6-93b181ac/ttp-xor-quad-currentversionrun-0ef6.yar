rule TTP_XOR_QUAD_CurrentVersionRun_0ef6 {
  strings:
    $key_0ef6 = { 5d 99 [2] 79 97 [2] 52 bb [2] 7c 99 [2] 68 82 [2] 67 98 [2] 79 85 [2] 7b 84 [2] 60 82 [2] 7c 85 [2] 60 aa }

  condition:
    any of them
}