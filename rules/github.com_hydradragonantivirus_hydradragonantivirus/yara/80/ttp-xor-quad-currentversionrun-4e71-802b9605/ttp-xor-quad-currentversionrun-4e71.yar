rule TTP_XOR_QUAD_CurrentVersionRun_4e71 {
  strings:
    $key_4e71 = { 1d 1e [2] 39 10 [2] 12 3c [2] 3c 1e [2] 28 05 [2] 27 1f [2] 39 02 [2] 3b 03 [2] 20 05 [2] 3c 02 [2] 20 2d }

  condition:
    any of them
}