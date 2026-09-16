rule TTP_XOR_QUAD_CurrentVersionRun_0c70 {
  strings:
    $key_0c70 = { 5f 1f [2] 7b 11 [2] 50 3d [2] 7e 1f [2] 6a 04 [2] 65 1e [2] 7b 03 [2] 79 02 [2] 62 04 [2] 7e 03 [2] 62 2c }

  condition:
    any of them
}