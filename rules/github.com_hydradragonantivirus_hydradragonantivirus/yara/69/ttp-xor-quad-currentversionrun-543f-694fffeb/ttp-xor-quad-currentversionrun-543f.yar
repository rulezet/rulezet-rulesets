rule TTP_XOR_QUAD_CurrentVersionRun_543f {
  strings:
    $key_543f = { 07 50 [2] 23 5e [2] 08 72 [2] 26 50 [2] 32 4b [2] 3d 51 [2] 23 4c [2] 21 4d [2] 3a 4b [2] 26 4c [2] 3a 63 }

  condition:
    any of them
}