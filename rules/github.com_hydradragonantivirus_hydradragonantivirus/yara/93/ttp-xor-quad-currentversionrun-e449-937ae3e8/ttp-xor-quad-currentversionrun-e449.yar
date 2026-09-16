rule TTP_XOR_QUAD_CurrentVersionRun_e449 {
  strings:
    $key_e449 = { b7 26 [2] 93 28 [2] b8 04 [2] 96 26 [2] 82 3d [2] 8d 27 [2] 93 3a [2] 91 3b [2] 8a 3d [2] 96 3a [2] 8a 15 }

  condition:
    any of them
}