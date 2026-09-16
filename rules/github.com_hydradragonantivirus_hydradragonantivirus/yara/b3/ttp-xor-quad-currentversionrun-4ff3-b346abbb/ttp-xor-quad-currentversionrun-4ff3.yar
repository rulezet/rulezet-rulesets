rule TTP_XOR_QUAD_CurrentVersionRun_4ff3 {
  strings:
    $key_4ff3 = { 1c 9c [2] 38 92 [2] 13 be [2] 3d 9c [2] 29 87 [2] 26 9d [2] 38 80 [2] 3a 81 [2] 21 87 [2] 3d 80 [2] 21 af }

  condition:
    any of them
}