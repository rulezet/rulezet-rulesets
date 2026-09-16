rule TTP_XOR_QUAD_CurrentVersionRun_61ea {
  strings:
    $key_61ea = { 32 85 [2] 16 8b [2] 3d a7 [2] 13 85 [2] 07 9e [2] 08 84 [2] 16 99 [2] 14 98 [2] 0f 9e [2] 13 99 [2] 0f b6 }

  condition:
    any of them
}