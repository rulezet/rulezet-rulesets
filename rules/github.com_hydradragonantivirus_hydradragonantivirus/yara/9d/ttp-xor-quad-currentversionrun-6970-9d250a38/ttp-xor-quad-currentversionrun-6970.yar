rule TTP_XOR_QUAD_CurrentVersionRun_6970 {
  strings:
    $key_6970 = { 3a 1f [2] 1e 11 [2] 35 3d [2] 1b 1f [2] 0f 04 [2] 00 1e [2] 1e 03 [2] 1c 02 [2] 07 04 [2] 1b 03 [2] 07 2c }

  condition:
    any of them
}