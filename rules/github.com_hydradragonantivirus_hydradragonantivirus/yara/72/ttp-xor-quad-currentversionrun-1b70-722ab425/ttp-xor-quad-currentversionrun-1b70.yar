rule TTP_XOR_QUAD_CurrentVersionRun_1b70 {
  strings:
    $key_1b70 = { 48 1f [2] 6c 11 [2] 47 3d [2] 69 1f [2] 7d 04 [2] 72 1e [2] 6c 03 [2] 6e 02 [2] 75 04 [2] 69 03 [2] 75 2c }

  condition:
    any of them
}