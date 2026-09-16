rule TTP_XOR_QUAD_CurrentVersionRun_6109 {
  strings:
    $key_6109 = { 32 66 [2] 16 68 [2] 3d 44 [2] 13 66 [2] 07 7d [2] 08 67 [2] 16 7a [2] 14 7b [2] 0f 7d [2] 13 7a [2] 0f 55 }

  condition:
    any of them
}