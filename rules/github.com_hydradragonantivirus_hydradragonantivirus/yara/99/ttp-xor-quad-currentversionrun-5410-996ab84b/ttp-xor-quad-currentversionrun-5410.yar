rule TTP_XOR_QUAD_CurrentVersionRun_5410 {
  strings:
    $key_5410 = { 07 7f [2] 23 71 [2] 08 5d [2] 26 7f [2] 32 64 [2] 3d 7e [2] 23 63 [2] 21 62 [2] 3a 64 [2] 26 63 [2] 3a 4c }

  condition:
    any of them
}