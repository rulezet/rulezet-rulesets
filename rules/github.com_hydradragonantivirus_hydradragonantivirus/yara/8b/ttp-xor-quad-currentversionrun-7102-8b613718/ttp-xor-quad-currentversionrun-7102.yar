rule TTP_XOR_QUAD_CurrentVersionRun_7102 {
  strings:
    $key_7102 = { 22 6d [2] 06 63 [2] 2d 4f [2] 03 6d [2] 17 76 [2] 18 6c [2] 06 71 [2] 04 70 [2] 1f 76 [2] 03 71 [2] 1f 5e }

  condition:
    any of them
}