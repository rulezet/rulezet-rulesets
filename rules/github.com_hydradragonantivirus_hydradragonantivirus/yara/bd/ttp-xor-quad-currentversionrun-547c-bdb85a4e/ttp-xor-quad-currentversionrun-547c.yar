rule TTP_XOR_QUAD_CurrentVersionRun_547c {
  strings:
    $key_547c = { 07 13 [2] 23 1d [2] 08 31 [2] 26 13 [2] 32 08 [2] 3d 12 [2] 23 0f [2] 21 0e [2] 3a 08 [2] 26 0f [2] 3a 20 }

  condition:
    any of them
}