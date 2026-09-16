rule TTP_XOR_QUAD_CurrentVersionRun_532d {
  strings:
    $key_532d = { 00 42 [2] 24 4c [2] 0f 60 [2] 21 42 [2] 35 59 [2] 3a 43 [2] 24 5e [2] 26 5f [2] 3d 59 [2] 21 5e [2] 3d 71 }

  condition:
    any of them
}