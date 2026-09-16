rule TTP_XOR_QUAD_CurrentVersionRun_7163 {
  strings:
    $key_7163 = { 22 0c [2] 06 02 [2] 2d 2e [2] 03 0c [2] 17 17 [2] 18 0d [2] 06 10 [2] 04 11 [2] 1f 17 [2] 03 10 [2] 1f 3f }

  condition:
    any of them
}