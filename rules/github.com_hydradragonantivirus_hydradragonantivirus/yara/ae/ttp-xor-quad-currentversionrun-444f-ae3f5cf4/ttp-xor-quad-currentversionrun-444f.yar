rule TTP_XOR_QUAD_CurrentVersionRun_444f {
  strings:
    $key_444f = { 17 20 [2] 33 2e [2] 18 02 [2] 36 20 [2] 22 3b [2] 2d 21 [2] 33 3c [2] 31 3d [2] 2a 3b [2] 36 3c [2] 2a 13 }

  condition:
    any of them
}