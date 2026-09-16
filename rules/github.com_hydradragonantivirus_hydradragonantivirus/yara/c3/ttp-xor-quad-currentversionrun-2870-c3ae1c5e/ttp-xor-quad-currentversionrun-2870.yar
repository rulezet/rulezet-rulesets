rule TTP_XOR_QUAD_CurrentVersionRun_2870 {
  strings:
    $key_2870 = { 7b 1f [2] 5f 11 [2] 74 3d [2] 5a 1f [2] 4e 04 [2] 41 1e [2] 5f 03 [2] 5d 02 [2] 46 04 [2] 5a 03 [2] 46 2c }

  condition:
    any of them
}