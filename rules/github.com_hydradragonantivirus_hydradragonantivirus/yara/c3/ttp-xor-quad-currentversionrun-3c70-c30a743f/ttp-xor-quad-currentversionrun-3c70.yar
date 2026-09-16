rule TTP_XOR_QUAD_CurrentVersionRun_3c70 {
  strings:
    $key_3c70 = { 6f 1f [2] 4b 11 [2] 60 3d [2] 4e 1f [2] 5a 04 [2] 55 1e [2] 4b 03 [2] 49 02 [2] 52 04 [2] 4e 03 [2] 52 2c }

  condition:
    any of them
}