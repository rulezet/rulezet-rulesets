rule TTP_XOR_QUAD_CurrentVersionRun_4f01 {
  strings:
    $key_4f01 = { 1c 6e [2] 38 60 [2] 13 4c [2] 3d 6e [2] 29 75 [2] 26 6f [2] 38 72 [2] 3a 73 [2] 21 75 [2] 3d 72 [2] 21 5d }

  condition:
    any of them
}