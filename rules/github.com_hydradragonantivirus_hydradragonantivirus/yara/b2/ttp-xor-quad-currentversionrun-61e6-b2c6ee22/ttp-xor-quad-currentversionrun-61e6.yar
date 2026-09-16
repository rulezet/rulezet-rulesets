rule TTP_XOR_QUAD_CurrentVersionRun_61e6 {
  strings:
    $key_61e6 = { 32 89 [2] 16 87 [2] 3d ab [2] 13 89 [2] 07 92 [2] 08 88 [2] 16 95 [2] 14 94 [2] 0f 92 [2] 13 95 [2] 0f ba }

  condition:
    any of them
}