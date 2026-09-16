rule TTP_XOR_QUAD_CurrentVersionRun_547d {
  strings:
    $key_547d = { 07 12 [2] 23 1c [2] 08 30 [2] 26 12 [2] 32 09 [2] 3d 13 [2] 23 0e [2] 21 0f [2] 3a 09 [2] 26 0e [2] 3a 21 }

  condition:
    any of them
}