rule TTP_XOR_QUAD_CurrentVersionRun_6170 {
  strings:
    $key_6170 = { 32 1f [2] 16 11 [2] 3d 3d [2] 13 1f [2] 07 04 [2] 08 1e [2] 16 03 [2] 14 02 [2] 0f 04 [2] 13 03 [2] 0f 2c }

  condition:
    any of them
}