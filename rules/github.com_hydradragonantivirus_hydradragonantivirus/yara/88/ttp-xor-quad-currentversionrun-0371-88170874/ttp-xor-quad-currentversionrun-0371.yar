rule TTP_XOR_QUAD_CurrentVersionRun_0371 {
  strings:
    $key_0371 = { 50 1e [2] 74 10 [2] 5f 3c [2] 71 1e [2] 65 05 [2] 6a 1f [2] 74 02 [2] 76 03 [2] 6d 05 [2] 71 02 [2] 6d 2d }

  condition:
    any of them
}