rule TTP_XOR_QUAD_CurrentVersionRun_611b {
  strings:
    $key_611b = { 32 74 [2] 16 7a [2] 3d 56 [2] 13 74 [2] 07 6f [2] 08 75 [2] 16 68 [2] 14 69 [2] 0f 6f [2] 13 68 [2] 0f 47 }

  condition:
    any of them
}