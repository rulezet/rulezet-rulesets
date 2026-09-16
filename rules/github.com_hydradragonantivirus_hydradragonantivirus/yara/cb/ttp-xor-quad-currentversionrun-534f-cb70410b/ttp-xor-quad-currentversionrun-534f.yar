rule TTP_XOR_QUAD_CurrentVersionRun_534f {
  strings:
    $key_534f = { 00 20 [2] 24 2e [2] 0f 02 [2] 21 20 [2] 35 3b [2] 3a 21 [2] 24 3c [2] 26 3d [2] 3d 3b [2] 21 3c [2] 3d 13 }

  condition:
    any of them
}