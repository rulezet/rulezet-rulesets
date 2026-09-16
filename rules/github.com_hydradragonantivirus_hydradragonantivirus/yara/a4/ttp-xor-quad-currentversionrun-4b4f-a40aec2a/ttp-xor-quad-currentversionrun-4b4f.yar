rule TTP_XOR_QUAD_CurrentVersionRun_4b4f {
  strings:
    $key_4b4f = { 18 20 [2] 3c 2e [2] 17 02 [2] 39 20 [2] 2d 3b [2] 22 21 [2] 3c 3c [2] 3e 3d [2] 25 3b [2] 39 3c [2] 25 13 }

  condition:
    any of them
}