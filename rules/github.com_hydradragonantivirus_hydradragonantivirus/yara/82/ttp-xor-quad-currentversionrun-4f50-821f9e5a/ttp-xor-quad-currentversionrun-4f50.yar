rule TTP_XOR_QUAD_CurrentVersionRun_4f50 {
  strings:
    $key_4f50 = { 1c 3f [2] 38 31 [2] 13 1d [2] 3d 3f [2] 29 24 [2] 26 3e [2] 38 23 [2] 3a 22 [2] 21 24 [2] 3d 23 [2] 21 0c }

  condition:
    any of them
}