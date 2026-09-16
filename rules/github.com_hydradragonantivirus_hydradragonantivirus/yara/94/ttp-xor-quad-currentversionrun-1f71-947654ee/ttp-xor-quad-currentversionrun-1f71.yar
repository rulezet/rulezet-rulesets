rule TTP_XOR_QUAD_CurrentVersionRun_1f71 {
  strings:
    $key_1f71 = { 4c 1e [2] 68 10 [2] 43 3c [2] 6d 1e [2] 79 05 [2] 76 1f [2] 68 02 [2] 6a 03 [2] 71 05 [2] 6d 02 [2] 71 2d }

  condition:
    any of them
}