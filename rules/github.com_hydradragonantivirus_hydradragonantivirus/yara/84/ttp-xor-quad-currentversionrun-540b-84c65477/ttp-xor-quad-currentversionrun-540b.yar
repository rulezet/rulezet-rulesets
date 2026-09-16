rule TTP_XOR_QUAD_CurrentVersionRun_540b {
  strings:
    $key_540b = { 07 64 [2] 23 6a [2] 08 46 [2] 26 64 [2] 32 7f [2] 3d 65 [2] 23 78 [2] 21 79 [2] 3a 7f [2] 26 78 [2] 3a 57 }

  condition:
    any of them
}