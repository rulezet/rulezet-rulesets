rule TTP_XOR_QUAD_CurrentVersionRun_534a {
  strings:
    $key_534a = { 00 25 [2] 24 2b [2] 0f 07 [2] 21 25 [2] 35 3e [2] 3a 24 [2] 24 39 [2] 26 38 [2] 3d 3e [2] 21 39 [2] 3d 16 }

  condition:
    any of them
}