rule TTP_XOR_QUAD_CurrentVersionRun_531f {
  strings:
    $key_531f = { 00 70 [2] 24 7e [2] 0f 52 [2] 21 70 [2] 35 6b [2] 3a 71 [2] 24 6c [2] 26 6d [2] 3d 6b [2] 21 6c [2] 3d 43 }

  condition:
    any of them
}