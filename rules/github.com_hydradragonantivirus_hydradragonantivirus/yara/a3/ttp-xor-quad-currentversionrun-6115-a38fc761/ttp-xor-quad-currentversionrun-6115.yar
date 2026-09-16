rule TTP_XOR_QUAD_CurrentVersionRun_6115 {
  strings:
    $key_6115 = { 32 7a [2] 16 74 [2] 3d 58 [2] 13 7a [2] 07 61 [2] 08 7b [2] 16 66 [2] 14 67 [2] 0f 61 [2] 13 66 [2] 0f 49 }

  condition:
    any of them
}