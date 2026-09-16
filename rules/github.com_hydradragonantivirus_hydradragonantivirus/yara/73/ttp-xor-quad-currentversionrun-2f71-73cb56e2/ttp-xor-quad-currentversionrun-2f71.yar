rule TTP_XOR_QUAD_CurrentVersionRun_2f71 {
  strings:
    $key_2f71 = { 7c 1e [2] 58 10 [2] 73 3c [2] 5d 1e [2] 49 05 [2] 46 1f [2] 58 02 [2] 5a 03 [2] 41 05 [2] 5d 02 [2] 41 2d }

  condition:
    any of them
}