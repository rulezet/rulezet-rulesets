rule TTP_XOR_QUAD_CurrentVersionRun_6a52 {
  strings:
    $key_6a52 = { 39 3d [2] 1d 33 [2] 36 1f [2] 18 3d [2] 0c 26 [2] 03 3c [2] 1d 21 [2] 1f 20 [2] 04 26 [2] 18 21 [2] 04 0e }

  condition:
    any of them
}