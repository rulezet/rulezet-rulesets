rule TTP_XOR_QUAD_CurrentVersionRun_1b52 {
  strings:
    $key_1b52 = { 48 3d [2] 6c 33 [2] 47 1f [2] 69 3d [2] 7d 26 [2] 72 3c [2] 6c 21 [2] 6e 20 [2] 75 26 [2] 69 21 [2] 75 0e }

  condition:
    any of them
}