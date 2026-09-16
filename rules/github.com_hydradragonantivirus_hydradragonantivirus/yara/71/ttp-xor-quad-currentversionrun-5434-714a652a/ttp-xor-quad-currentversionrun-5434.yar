rule TTP_XOR_QUAD_CurrentVersionRun_5434 {
  strings:
    $key_5434 = { 07 5b [2] 23 55 [2] 08 79 [2] 26 5b [2] 32 40 [2] 3d 5a [2] 23 47 [2] 21 46 [2] 3a 40 [2] 26 47 [2] 3a 68 }

  condition:
    any of them
}