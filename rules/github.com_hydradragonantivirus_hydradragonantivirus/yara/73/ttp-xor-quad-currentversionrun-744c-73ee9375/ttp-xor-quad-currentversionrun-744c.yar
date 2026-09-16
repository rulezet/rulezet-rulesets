rule TTP_XOR_QUAD_CurrentVersionRun_744c {
  strings:
    $key_744c = { 27 23 [2] 03 2d [2] 28 01 [2] 06 23 [2] 12 38 [2] 1d 22 [2] 03 3f [2] 01 3e [2] 1a 38 [2] 06 3f [2] 1a 10 }

  condition:
    any of them
}