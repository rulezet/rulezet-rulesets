rule TTP_XOR_QUAD_CurrentVersionRun_3bf6 {
  strings:
    $key_3bf6 = { 68 99 [2] 4c 97 [2] 67 bb [2] 49 99 [2] 5d 82 [2] 52 98 [2] 4c 85 [2] 4e 84 [2] 55 82 [2] 49 85 [2] 55 aa }

  condition:
    any of them
}