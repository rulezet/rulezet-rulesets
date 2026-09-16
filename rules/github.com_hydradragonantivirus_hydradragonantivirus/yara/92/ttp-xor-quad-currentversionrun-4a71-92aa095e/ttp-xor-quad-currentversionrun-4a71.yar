rule TTP_XOR_QUAD_CurrentVersionRun_4a71 {
  strings:
    $key_4a71 = { 19 1e [2] 3d 10 [2] 16 3c [2] 38 1e [2] 2c 05 [2] 23 1f [2] 3d 02 [2] 3f 03 [2] 24 05 [2] 38 02 [2] 24 2d }

  condition:
    any of them
}