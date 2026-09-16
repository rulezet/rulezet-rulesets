rule TTP_XOR_QUAD_CurrentVersionRun_6ef6 {
  strings:
    $key_6ef6 = { 3d 99 [2] 19 97 [2] 32 bb [2] 1c 99 [2] 08 82 [2] 07 98 [2] 19 85 [2] 1b 84 [2] 00 82 [2] 1c 85 [2] 00 aa }

  condition:
    any of them
}