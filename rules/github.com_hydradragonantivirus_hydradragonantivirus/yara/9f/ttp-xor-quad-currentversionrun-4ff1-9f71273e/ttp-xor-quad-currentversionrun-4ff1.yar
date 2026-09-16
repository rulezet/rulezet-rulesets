rule TTP_XOR_QUAD_CurrentVersionRun_4ff1 {
  strings:
    $key_4ff1 = { 1c 9e [2] 38 90 [2] 13 bc [2] 3d 9e [2] 29 85 [2] 26 9f [2] 38 82 [2] 3a 83 [2] 21 85 [2] 3d 82 [2] 21 ad }

  condition:
    any of them
}