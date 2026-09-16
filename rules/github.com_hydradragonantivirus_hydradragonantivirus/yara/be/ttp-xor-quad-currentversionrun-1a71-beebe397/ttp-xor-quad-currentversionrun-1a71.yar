rule TTP_XOR_QUAD_CurrentVersionRun_1a71 {
  strings:
    $key_1a71 = { 49 1e [2] 6d 10 [2] 46 3c [2] 68 1e [2] 7c 05 [2] 73 1f [2] 6d 02 [2] 6f 03 [2] 74 05 [2] 68 02 [2] 74 2d }

  condition:
    any of them
}