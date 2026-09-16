rule TTP_XOR_QUAD_CurrentVersionRun_54f9 {
  strings:
    $key_54f9 = { 07 96 [2] 23 98 [2] 08 b4 [2] 26 96 [2] 32 8d [2] 3d 97 [2] 23 8a [2] 21 8b [2] 3a 8d [2] 26 8a [2] 3a a5 }

  condition:
    any of them
}