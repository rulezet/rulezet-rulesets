rule TTP_XOR_QUAD_CurrentVersionRun_71ef {
  strings:
    $key_71ef = { 22 80 [2] 06 8e [2] 2d a2 [2] 03 80 [2] 17 9b [2] 18 81 [2] 06 9c [2] 04 9d [2] 1f 9b [2] 03 9c [2] 1f b3 }

  condition:
    any of them
}