rule TTP_XOR_QUAD_CurrentVersionRun_2570 {
  strings:
    $key_2570 = { 76 1f [2] 52 11 [2] 79 3d [2] 57 1f [2] 43 04 [2] 4c 1e [2] 52 03 [2] 50 02 [2] 4b 04 [2] 57 03 [2] 4b 2c }

  condition:
    any of them
}