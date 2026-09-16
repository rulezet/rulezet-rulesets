rule TTP_XOR_QUAD_CurrentVersionRun_5f4f {
  strings:
    $key_5f4f = { 0c 20 [2] 28 2e [2] 03 02 [2] 2d 20 [2] 39 3b [2] 36 21 [2] 28 3c [2] 2a 3d [2] 31 3b [2] 2d 3c [2] 31 13 }

  condition:
    any of them
}