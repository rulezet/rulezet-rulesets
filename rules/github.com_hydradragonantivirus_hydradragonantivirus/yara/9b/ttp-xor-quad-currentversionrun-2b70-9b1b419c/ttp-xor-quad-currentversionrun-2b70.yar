rule TTP_XOR_QUAD_CurrentVersionRun_2b70 {
  strings:
    $key_2b70 = { 78 1f [2] 5c 11 [2] 77 3d [2] 59 1f [2] 4d 04 [2] 42 1e [2] 5c 03 [2] 5e 02 [2] 45 04 [2] 59 03 [2] 45 2c }

  condition:
    any of them
}