rule TTP_XOR_QUAD_CurrentVersionRun_3ff6 {
  strings:
    $key_3ff6 = { 6c 99 [2] 48 97 [2] 63 bb [2] 4d 99 [2] 59 82 [2] 56 98 [2] 48 85 [2] 4a 84 [2] 51 82 [2] 4d 85 [2] 51 aa }

  condition:
    any of them
}