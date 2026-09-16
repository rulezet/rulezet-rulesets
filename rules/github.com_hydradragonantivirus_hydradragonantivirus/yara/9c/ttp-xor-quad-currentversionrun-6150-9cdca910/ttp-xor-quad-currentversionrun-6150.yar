rule TTP_XOR_QUAD_CurrentVersionRun_6150 {
  strings:
    $key_6150 = { 32 3f [2] 16 31 [2] 3d 1d [2] 13 3f [2] 07 24 [2] 08 3e [2] 16 23 [2] 14 22 [2] 0f 24 [2] 13 23 [2] 0f 0c }

  condition:
    any of them
}