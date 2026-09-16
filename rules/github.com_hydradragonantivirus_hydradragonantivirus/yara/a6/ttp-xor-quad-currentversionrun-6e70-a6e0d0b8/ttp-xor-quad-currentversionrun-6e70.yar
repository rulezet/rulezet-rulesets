rule TTP_XOR_QUAD_CurrentVersionRun_6e70 {
  strings:
    $key_6e70 = { 3d 1f [2] 19 11 [2] 32 3d [2] 1c 1f [2] 08 04 [2] 07 1e [2] 19 03 [2] 1b 02 [2] 00 04 [2] 1c 03 [2] 00 2c }

  condition:
    any of them
}