rule TTP_XOR_QUAD_CurrentVersionRun_543b {
  strings:
    $key_543b = { 07 54 [2] 23 5a [2] 08 76 [2] 26 54 [2] 32 4f [2] 3d 55 [2] 23 48 [2] 21 49 [2] 3a 4f [2] 26 48 [2] 3a 67 }

  condition:
    any of them
}