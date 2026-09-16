rule TTP_XOR_QUAD_CurrentVersionRun_2af6 {
  strings:
    $key_2af6 = { 79 99 [2] 5d 97 [2] 76 bb [2] 58 99 [2] 4c 82 [2] 43 98 [2] 5d 85 [2] 5f 84 [2] 44 82 [2] 58 85 [2] 44 aa }

  condition:
    any of them
}