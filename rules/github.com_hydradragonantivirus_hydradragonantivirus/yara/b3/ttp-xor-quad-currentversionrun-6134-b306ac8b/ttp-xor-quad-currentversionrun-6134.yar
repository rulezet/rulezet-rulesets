rule TTP_XOR_QUAD_CurrentVersionRun_6134 {
  strings:
    $key_6134 = { 32 5b [2] 16 55 [2] 3d 79 [2] 13 5b [2] 07 40 [2] 08 5a [2] 16 47 [2] 14 46 [2] 0f 40 [2] 13 47 [2] 0f 68 }

  condition:
    any of them
}