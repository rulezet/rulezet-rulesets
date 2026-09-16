rule TTP_XOR_QUAD_CurrentVersionRun_7b4f {
  strings:
    $key_7b4f = { 28 20 [2] 0c 2e [2] 27 02 [2] 09 20 [2] 1d 3b [2] 12 21 [2] 0c 3c [2] 0e 3d [2] 15 3b [2] 09 3c [2] 15 13 }

  condition:
    any of them
}