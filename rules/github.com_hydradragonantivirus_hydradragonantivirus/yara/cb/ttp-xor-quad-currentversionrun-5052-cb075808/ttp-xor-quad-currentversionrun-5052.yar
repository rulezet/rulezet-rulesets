rule TTP_XOR_QUAD_CurrentVersionRun_5052 {
  strings:
    $key_5052 = { 03 3d [2] 27 33 [2] 0c 1f [2] 22 3d [2] 36 26 [2] 39 3c [2] 27 21 [2] 25 20 [2] 3e 26 [2] 22 21 [2] 3e 0e }

  condition:
    any of them
}