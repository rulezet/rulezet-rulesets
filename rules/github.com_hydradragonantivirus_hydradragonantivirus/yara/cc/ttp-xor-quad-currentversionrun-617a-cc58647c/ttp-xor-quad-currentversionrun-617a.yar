rule TTP_XOR_QUAD_CurrentVersionRun_617a {
  strings:
    $key_617a = { 32 15 [2] 16 1b [2] 3d 37 [2] 13 15 [2] 07 0e [2] 08 14 [2] 16 09 [2] 14 08 [2] 0f 0e [2] 13 09 [2] 0f 26 }

  condition:
    any of them
}