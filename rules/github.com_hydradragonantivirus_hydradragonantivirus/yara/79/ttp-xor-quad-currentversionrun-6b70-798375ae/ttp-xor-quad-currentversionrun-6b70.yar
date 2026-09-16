rule TTP_XOR_QUAD_CurrentVersionRun_6b70 {
  strings:
    $key_6b70 = { 38 1f [2] 1c 11 [2] 37 3d [2] 19 1f [2] 0d 04 [2] 02 1e [2] 1c 03 [2] 1e 02 [2] 05 04 [2] 19 03 [2] 05 2c }

  condition:
    any of them
}