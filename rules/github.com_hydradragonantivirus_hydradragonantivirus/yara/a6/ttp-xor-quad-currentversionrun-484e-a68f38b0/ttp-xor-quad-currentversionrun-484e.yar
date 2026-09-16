rule TTP_XOR_QUAD_CurrentVersionRun_484e {
  strings:
    $key_484e = { 1b 21 [2] 3f 2f [2] 14 03 [2] 3a 21 [2] 2e 3a [2] 21 20 [2] 3f 3d [2] 3d 3c [2] 26 3a [2] 3a 3d [2] 26 12 }

  condition:
    any of them
}