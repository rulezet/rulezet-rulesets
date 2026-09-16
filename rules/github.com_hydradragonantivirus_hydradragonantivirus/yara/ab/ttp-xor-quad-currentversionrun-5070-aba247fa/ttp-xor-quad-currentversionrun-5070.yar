rule TTP_XOR_QUAD_CurrentVersionRun_5070 {
  strings:
    $key_5070 = { 03 1f [2] 27 11 [2] 0c 3d [2] 22 1f [2] 36 04 [2] 39 1e [2] 27 03 [2] 25 02 [2] 3e 04 [2] 22 03 [2] 3e 2c }

  condition:
    any of them
}