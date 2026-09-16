rule TTP_XOR_QUAD_CurrentVersionRun_0b52 {
  strings:
    $key_0b52 = { 58 3d [2] 7c 33 [2] 57 1f [2] 79 3d [2] 6d 26 [2] 62 3c [2] 7c 21 [2] 7e 20 [2] 65 26 [2] 79 21 [2] 65 0e }

  condition:
    any of them
}