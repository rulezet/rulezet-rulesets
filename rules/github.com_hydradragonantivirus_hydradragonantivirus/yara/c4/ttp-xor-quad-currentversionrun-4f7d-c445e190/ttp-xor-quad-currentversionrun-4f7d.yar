rule TTP_XOR_QUAD_CurrentVersionRun_4f7d {
  strings:
    $key_4f7d = { 1c 12 [2] 38 1c [2] 13 30 [2] 3d 12 [2] 29 09 [2] 26 13 [2] 38 0e [2] 3a 0f [2] 21 09 [2] 3d 0e [2] 21 21 }

  condition:
    any of them
}