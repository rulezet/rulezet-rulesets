rule TTP_XOR_QUAD_CurrentVersionRun_5a4f {
  strings:
    $key_5a4f = { 09 20 [2] 2d 2e [2] 06 02 [2] 28 20 [2] 3c 3b [2] 33 21 [2] 2d 3c [2] 2f 3d [2] 34 3b [2] 28 3c [2] 34 13 }

  condition:
    any of them
}