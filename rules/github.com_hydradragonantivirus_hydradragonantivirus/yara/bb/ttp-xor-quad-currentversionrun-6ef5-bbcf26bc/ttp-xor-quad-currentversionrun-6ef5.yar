rule TTP_XOR_QUAD_CurrentVersionRun_6ef5 {
  strings:
    $key_6ef5 = { 3d 9a [2] 19 94 [2] 32 b8 [2] 1c 9a [2] 08 81 [2] 07 9b [2] 19 86 [2] 1b 87 [2] 00 81 [2] 1c 86 [2] 00 a9 }

  condition:
    any of them
}