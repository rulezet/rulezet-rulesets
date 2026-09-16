rule TTP_XOR_QUAD_CurrentVersionRun_6a70 {
  strings:
    $key_6a70 = { 39 1f [2] 1d 11 [2] 36 3d [2] 18 1f [2] 0c 04 [2] 03 1e [2] 1d 03 [2] 1f 02 [2] 04 04 [2] 18 03 [2] 04 2c }

  condition:
    any of them
}