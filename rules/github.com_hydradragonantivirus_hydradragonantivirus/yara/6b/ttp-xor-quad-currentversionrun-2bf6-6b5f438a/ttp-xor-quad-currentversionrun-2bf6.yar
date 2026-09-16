rule TTP_XOR_QUAD_CurrentVersionRun_2bf6 {
  strings:
    $key_2bf6 = { 78 99 [2] 5c 97 [2] 77 bb [2] 59 99 [2] 4d 82 [2] 42 98 [2] 5c 85 [2] 5e 84 [2] 45 82 [2] 59 85 [2] 45 aa }

  condition:
    any of them
}