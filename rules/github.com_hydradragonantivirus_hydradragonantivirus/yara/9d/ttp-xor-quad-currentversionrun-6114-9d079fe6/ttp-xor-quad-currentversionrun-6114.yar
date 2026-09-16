rule TTP_XOR_QUAD_CurrentVersionRun_6114 {
  strings:
    $key_6114 = { 32 7b [2] 16 75 [2] 3d 59 [2] 13 7b [2] 07 60 [2] 08 7a [2] 16 67 [2] 14 66 [2] 0f 60 [2] 13 67 [2] 0f 48 }

  condition:
    any of them
}