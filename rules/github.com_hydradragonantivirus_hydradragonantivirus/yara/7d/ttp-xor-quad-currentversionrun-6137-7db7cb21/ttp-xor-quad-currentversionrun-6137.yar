rule TTP_XOR_QUAD_CurrentVersionRun_6137 {
  strings:
    $key_6137 = { 32 58 [2] 16 56 [2] 3d 7a [2] 13 58 [2] 07 43 [2] 08 59 [2] 16 44 [2] 14 45 [2] 0f 43 [2] 13 44 [2] 0f 6b }

  condition:
    any of them
}