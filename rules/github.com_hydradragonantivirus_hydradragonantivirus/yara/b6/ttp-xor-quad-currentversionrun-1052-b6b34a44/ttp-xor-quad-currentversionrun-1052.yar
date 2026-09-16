rule TTP_XOR_QUAD_CurrentVersionRun_1052 {
  strings:
    $key_1052 = { 43 3d [2] 67 33 [2] 4c 1f [2] 62 3d [2] 76 26 [2] 79 3c [2] 67 21 [2] 65 20 [2] 7e 26 [2] 62 21 [2] 7e 0e }

  condition:
    any of them
}