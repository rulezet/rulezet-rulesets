rule TTP_XOR_QUAD_CurrentVersionRun_7b52 {
  strings:
    $key_7b52 = { 28 3d [2] 0c 33 [2] 27 1f [2] 09 3d [2] 1d 26 [2] 12 3c [2] 0c 21 [2] 0e 20 [2] 15 26 [2] 09 21 [2] 15 0e }

  condition:
    any of them
}