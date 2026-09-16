rule TTP_XOR_QUAD_CurrentVersionRun_1d70 {
  strings:
    $key_1d70 = { 4e 1f [2] 6a 11 [2] 41 3d [2] 6f 1f [2] 7b 04 [2] 74 1e [2] 6a 03 [2] 68 02 [2] 73 04 [2] 6f 03 [2] 73 2c }

  condition:
    any of them
}