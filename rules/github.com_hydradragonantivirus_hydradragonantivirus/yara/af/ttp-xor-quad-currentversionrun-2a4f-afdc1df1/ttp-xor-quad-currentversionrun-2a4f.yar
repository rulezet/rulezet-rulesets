rule TTP_XOR_QUAD_CurrentVersionRun_2a4f {
  strings:
    $key_2a4f = { 79 20 [2] 5d 2e [2] 76 02 [2] 58 20 [2] 4c 3b [2] 43 21 [2] 5d 3c [2] 5f 3d [2] 44 3b [2] 58 3c [2] 44 13 }

  condition:
    any of them
}