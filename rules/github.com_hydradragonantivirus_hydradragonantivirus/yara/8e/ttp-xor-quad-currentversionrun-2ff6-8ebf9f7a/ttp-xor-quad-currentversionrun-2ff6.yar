rule TTP_XOR_QUAD_CurrentVersionRun_2ff6 {
  strings:
    $key_2ff6 = { 7c 99 [2] 58 97 [2] 73 bb [2] 5d 99 [2] 49 82 [2] 46 98 [2] 58 85 [2] 5a 84 [2] 41 82 [2] 5d 85 [2] 41 aa }

  condition:
    any of them
}