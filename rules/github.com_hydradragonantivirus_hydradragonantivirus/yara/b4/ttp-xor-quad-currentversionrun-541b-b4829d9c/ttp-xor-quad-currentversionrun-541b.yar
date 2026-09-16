rule TTP_XOR_QUAD_CurrentVersionRun_541b {
  strings:
    $key_541b = { 07 74 [2] 23 7a [2] 08 56 [2] 26 74 [2] 32 6f [2] 3d 75 [2] 23 68 [2] 21 69 [2] 3a 6f [2] 26 68 [2] 3a 47 }

  condition:
    any of them
}