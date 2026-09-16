rule TTP_XOR_QUAD_CurrentVersionRun_6d70 {
  strings:
    $key_6d70 = { 3e 1f [2] 1a 11 [2] 31 3d [2] 1f 1f [2] 0b 04 [2] 04 1e [2] 1a 03 [2] 18 02 [2] 03 04 [2] 1f 03 [2] 03 2c }

  condition:
    any of them
}