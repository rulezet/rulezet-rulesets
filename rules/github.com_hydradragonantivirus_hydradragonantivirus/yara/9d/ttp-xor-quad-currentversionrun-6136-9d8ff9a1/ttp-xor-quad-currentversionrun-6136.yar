rule TTP_XOR_QUAD_CurrentVersionRun_6136 {
  strings:
    $key_6136 = { 32 59 [2] 16 57 [2] 3d 7b [2] 13 59 [2] 07 42 [2] 08 58 [2] 16 45 [2] 14 44 [2] 0f 42 [2] 13 45 [2] 0f 6a }

  condition:
    any of them
}