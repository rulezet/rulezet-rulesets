rule TTP_XOR_QUAD_CurrentVersionRun_6123 {
  strings:
    $key_6123 = { 32 4c [2] 16 42 [2] 3d 6e [2] 13 4c [2] 07 57 [2] 08 4d [2] 16 50 [2] 14 51 [2] 0f 57 [2] 13 50 [2] 0f 7f }

  condition:
    any of them
}