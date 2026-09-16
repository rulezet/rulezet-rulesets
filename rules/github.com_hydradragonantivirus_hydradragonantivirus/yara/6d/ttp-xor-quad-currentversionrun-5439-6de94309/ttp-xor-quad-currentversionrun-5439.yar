rule TTP_XOR_QUAD_CurrentVersionRun_5439 {
  strings:
    $key_5439 = { 07 56 [2] 23 58 [2] 08 74 [2] 26 56 [2] 32 4d [2] 3d 57 [2] 23 4a [2] 21 4b [2] 3a 4d [2] 26 4a [2] 3a 65 }

  condition:
    any of them
}