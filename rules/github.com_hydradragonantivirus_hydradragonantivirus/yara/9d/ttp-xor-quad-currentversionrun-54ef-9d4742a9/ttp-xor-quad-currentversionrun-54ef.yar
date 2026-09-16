rule TTP_XOR_QUAD_CurrentVersionRun_54ef {
  strings:
    $key_54ef = { 07 80 [2] 23 8e [2] 08 a2 [2] 26 80 [2] 32 9b [2] 3d 81 [2] 23 9c [2] 21 9d [2] 3a 9b [2] 26 9c [2] 3a b3 }

  condition:
    any of them
}