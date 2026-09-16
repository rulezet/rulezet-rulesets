rule TTP_XOR_QUAD_CurrentVersionRun_487c {
  strings:
    $key_487c = { 1b 13 [2] 3f 1d [2] 14 31 [2] 3a 13 [2] 2e 08 [2] 21 12 [2] 3f 0f [2] 3d 0e [2] 26 08 [2] 3a 0f [2] 26 20 }

  condition:
    any of them
}