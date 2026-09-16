rule TTP_XOR_QUAD_CurrentVersionRun_4f3b {
  strings:
    $key_4f3b = { 1c 54 [2] 38 5a [2] 13 76 [2] 3d 54 [2] 29 4f [2] 26 55 [2] 38 48 [2] 3a 49 [2] 21 4f [2] 3d 48 [2] 21 67 }

  condition:
    any of them
}