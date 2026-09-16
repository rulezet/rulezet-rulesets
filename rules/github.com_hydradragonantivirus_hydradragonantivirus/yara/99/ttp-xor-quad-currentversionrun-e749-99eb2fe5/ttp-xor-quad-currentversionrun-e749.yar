rule TTP_XOR_QUAD_CurrentVersionRun_e749 {
  strings:
    $key_e749 = { b4 26 [2] 90 28 [2] bb 04 [2] 95 26 [2] 81 3d [2] 8e 27 [2] 90 3a [2] 92 3b [2] 89 3d [2] 95 3a [2] 89 15 }

  condition:
    any of them
}