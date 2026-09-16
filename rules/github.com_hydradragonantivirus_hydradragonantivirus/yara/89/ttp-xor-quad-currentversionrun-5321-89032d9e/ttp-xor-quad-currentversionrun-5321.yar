rule TTP_XOR_QUAD_CurrentVersionRun_5321 {
  strings:
    $key_5321 = { 00 4e [2] 24 40 [2] 0f 6c [2] 21 4e [2] 35 55 [2] 3a 4f [2] 24 52 [2] 26 53 [2] 3d 55 [2] 21 52 [2] 3d 7d }

  condition:
    any of them
}