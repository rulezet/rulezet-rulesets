rule TTP_XOR_QUAD_CurrentVersionRun_0471 {
  strings:
    $key_0471 = { 57 1e [2] 73 10 [2] 58 3c [2] 76 1e [2] 62 05 [2] 6d 1f [2] 73 02 [2] 71 03 [2] 6a 05 [2] 76 02 [2] 6a 2d }

  condition:
    any of them
}