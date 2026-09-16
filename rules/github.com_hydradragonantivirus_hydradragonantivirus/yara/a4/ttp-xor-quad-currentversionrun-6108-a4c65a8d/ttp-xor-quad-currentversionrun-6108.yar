rule TTP_XOR_QUAD_CurrentVersionRun_6108 {
  strings:
    $key_6108 = { 32 67 [2] 16 69 [2] 3d 45 [2] 13 67 [2] 07 7c [2] 08 66 [2] 16 7b [2] 14 7a [2] 0f 7c [2] 13 7b [2] 0f 54 }

  condition:
    any of them
}