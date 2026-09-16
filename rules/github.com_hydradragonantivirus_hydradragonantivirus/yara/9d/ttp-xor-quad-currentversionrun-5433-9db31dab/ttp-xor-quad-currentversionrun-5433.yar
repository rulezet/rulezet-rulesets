rule TTP_XOR_QUAD_CurrentVersionRun_5433 {
  strings:
    $key_5433 = { 07 5c [2] 23 52 [2] 08 7e [2] 26 5c [2] 32 47 [2] 3d 5d [2] 23 40 [2] 21 41 [2] 3a 47 [2] 26 40 [2] 3a 6f }

  condition:
    any of them
}