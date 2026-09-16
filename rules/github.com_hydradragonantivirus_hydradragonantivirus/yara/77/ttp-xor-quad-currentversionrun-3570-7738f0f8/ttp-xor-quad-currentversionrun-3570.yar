rule TTP_XOR_QUAD_CurrentVersionRun_3570 {
  strings:
    $key_3570 = { 66 1f [2] 42 11 [2] 69 3d [2] 47 1f [2] 53 04 [2] 5c 1e [2] 42 03 [2] 40 02 [2] 5b 04 [2] 47 03 [2] 5b 2c }

  condition:
    any of them
}