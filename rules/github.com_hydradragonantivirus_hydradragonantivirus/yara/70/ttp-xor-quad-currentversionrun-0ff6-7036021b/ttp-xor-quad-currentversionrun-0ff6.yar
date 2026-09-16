rule TTP_XOR_QUAD_CurrentVersionRun_0ff6 {
  strings:
    $key_0ff6 = { 5c 99 [2] 78 97 [2] 53 bb [2] 7d 99 [2] 69 82 [2] 66 98 [2] 78 85 [2] 7a 84 [2] 61 82 [2] 7d 85 [2] 61 aa }

  condition:
    any of them
}