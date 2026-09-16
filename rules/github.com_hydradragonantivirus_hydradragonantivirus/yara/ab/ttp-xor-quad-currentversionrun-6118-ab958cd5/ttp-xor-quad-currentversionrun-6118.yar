rule TTP_XOR_QUAD_CurrentVersionRun_6118 {
  strings:
    $key_6118 = { 32 77 [2] 16 79 [2] 3d 55 [2] 13 77 [2] 07 6c [2] 08 76 [2] 16 6b [2] 14 6a [2] 0f 6c [2] 13 6b [2] 0f 44 }

  condition:
    any of them
}