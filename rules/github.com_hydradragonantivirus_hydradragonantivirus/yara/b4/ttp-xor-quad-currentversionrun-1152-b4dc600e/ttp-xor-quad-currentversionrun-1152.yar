rule TTP_XOR_QUAD_CurrentVersionRun_1152 {
  strings:
    $key_1152 = { 42 3d [2] 66 33 [2] 4d 1f [2] 63 3d [2] 77 26 [2] 78 3c [2] 66 21 [2] 64 20 [2] 7f 26 [2] 63 21 [2] 7f 0e }

  condition:
    any of them
}