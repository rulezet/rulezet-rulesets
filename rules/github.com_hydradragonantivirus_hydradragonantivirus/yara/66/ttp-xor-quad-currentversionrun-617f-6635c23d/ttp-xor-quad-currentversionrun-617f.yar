rule TTP_XOR_QUAD_CurrentVersionRun_617f {
  strings:
    $key_617f = { 32 10 [2] 16 1e [2] 3d 32 [2] 13 10 [2] 07 0b [2] 08 11 [2] 16 0c [2] 14 0d [2] 0f 0b [2] 13 0c [2] 0f 23 }

  condition:
    any of them
}