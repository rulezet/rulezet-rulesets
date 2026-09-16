rule TTP_XOR_QUAD_CurrentVersionRun_6f4f {
  strings:
    $key_6f4f = { 3c 20 [2] 18 2e [2] 33 02 [2] 1d 20 [2] 09 3b [2] 06 21 [2] 18 3c [2] 1a 3d [2] 01 3b [2] 1d 3c [2] 01 13 }

  condition:
    any of them
}