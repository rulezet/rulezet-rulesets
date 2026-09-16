rule TTP_XOR_QUAD_CurrentVersionRun_2c70 {
  strings:
    $key_2c70 = { 7f 1f [2] 5b 11 [2] 70 3d [2] 5e 1f [2] 4a 04 [2] 45 1e [2] 5b 03 [2] 59 02 [2] 42 04 [2] 5e 03 [2] 42 2c }

  condition:
    any of them
}