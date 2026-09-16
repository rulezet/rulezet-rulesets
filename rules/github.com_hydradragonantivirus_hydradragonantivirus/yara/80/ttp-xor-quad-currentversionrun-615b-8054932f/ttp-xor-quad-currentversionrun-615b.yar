rule TTP_XOR_QUAD_CurrentVersionRun_615b {
  strings:
    $key_615b = { 32 34 [2] 16 3a [2] 3d 16 [2] 13 34 [2] 07 2f [2] 08 35 [2] 16 28 [2] 14 29 [2] 0f 2f [2] 13 28 [2] 0f 07 }

  condition:
    any of them
}