rule TTP_XOR_QUAD_CurrentVersionRun_483b {
  strings:
    $key_483b = { 1b 54 [2] 3f 5a [2] 14 76 [2] 3a 54 [2] 2e 4f [2] 21 55 [2] 3f 48 [2] 3d 49 [2] 26 4f [2] 3a 48 [2] 26 67 }

  condition:
    any of them
}