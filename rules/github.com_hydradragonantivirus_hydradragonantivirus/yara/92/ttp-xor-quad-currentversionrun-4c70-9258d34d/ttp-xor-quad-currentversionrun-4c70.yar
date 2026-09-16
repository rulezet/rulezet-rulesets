rule TTP_XOR_QUAD_CurrentVersionRun_4c70 {
  strings:
    $key_4c70 = { 1f 1f [2] 3b 11 [2] 10 3d [2] 3e 1f [2] 2a 04 [2] 25 1e [2] 3b 03 [2] 39 02 [2] 22 04 [2] 3e 03 [2] 22 2c }

  condition:
    any of them
}