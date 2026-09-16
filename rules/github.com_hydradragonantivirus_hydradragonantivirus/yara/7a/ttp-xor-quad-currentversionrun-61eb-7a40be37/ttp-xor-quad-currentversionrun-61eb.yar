rule TTP_XOR_QUAD_CurrentVersionRun_61eb {
  strings:
    $key_61eb = { 32 84 [2] 16 8a [2] 3d a6 [2] 13 84 [2] 07 9f [2] 08 85 [2] 16 98 [2] 14 99 [2] 0f 9f [2] 13 98 [2] 0f b7 }

  condition:
    any of them
}