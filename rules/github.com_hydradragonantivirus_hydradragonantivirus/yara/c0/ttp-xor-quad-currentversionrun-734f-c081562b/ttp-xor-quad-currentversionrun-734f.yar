rule TTP_XOR_QUAD_CurrentVersionRun_734f {
  strings:
    $key_734f = { 20 20 [2] 04 2e [2] 2f 02 [2] 01 20 [2] 15 3b [2] 1a 21 [2] 04 3c [2] 06 3d [2] 1d 3b [2] 01 3c [2] 1d 13 }

  condition:
    any of them
}