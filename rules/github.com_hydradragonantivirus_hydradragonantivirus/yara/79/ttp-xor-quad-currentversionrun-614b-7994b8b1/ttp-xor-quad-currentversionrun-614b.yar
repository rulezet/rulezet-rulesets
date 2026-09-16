rule TTP_XOR_QUAD_CurrentVersionRun_614b {
  strings:
    $key_614b = { 32 24 [2] 16 2a [2] 3d 06 [2] 13 24 [2] 07 3f [2] 08 25 [2] 16 38 [2] 14 39 [2] 0f 3f [2] 13 38 [2] 0f 17 }

  condition:
    any of them
}