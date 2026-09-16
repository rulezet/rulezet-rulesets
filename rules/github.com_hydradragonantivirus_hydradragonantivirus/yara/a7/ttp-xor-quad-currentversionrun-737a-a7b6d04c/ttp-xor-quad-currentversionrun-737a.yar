rule TTP_XOR_QUAD_CurrentVersionRun_737a {
  strings:
    $key_737a = { 20 15 [2] 04 1b [2] 2f 37 [2] 01 15 [2] 15 0e [2] 1a 14 [2] 04 09 [2] 06 08 [2] 1d 0e [2] 01 09 [2] 1d 26 }

  condition:
    any of them
}