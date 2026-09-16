rule TTP_XOR_QUAD_CurrentVersionRun_4e52 {
  strings:
    $key_4e52 = { 1d 3d [2] 39 33 [2] 12 1f [2] 3c 3d [2] 28 26 [2] 27 3c [2] 39 21 [2] 3b 20 [2] 20 26 [2] 3c 21 [2] 20 0e }

  condition:
    any of them
}