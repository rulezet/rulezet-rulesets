rule TTP_XOR_QUAD_CurrentVersionRun_71ec {
  strings:
    $key_71ec = { 22 83 [2] 06 8d [2] 2d a1 [2] 03 83 [2] 17 98 [2] 18 82 [2] 06 9f [2] 04 9e [2] 1f 98 [2] 03 9f [2] 1f b0 }

  condition:
    any of them
}