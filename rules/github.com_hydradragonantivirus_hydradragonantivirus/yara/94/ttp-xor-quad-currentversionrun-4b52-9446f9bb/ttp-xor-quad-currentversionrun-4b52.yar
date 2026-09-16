rule TTP_XOR_QUAD_CurrentVersionRun_4b52 {
  strings:
    $key_4b52 = { 18 3d [2] 3c 33 [2] 17 1f [2] 39 3d [2] 2d 26 [2] 22 3c [2] 3c 21 [2] 3e 20 [2] 25 26 [2] 39 21 [2] 25 0e }

  condition:
    any of them
}