rule TTP_XOR_QUAD_CurrentVersionRun_6652 {
  strings:
    $key_6652 = { 35 3d [2] 11 33 [2] 3a 1f [2] 14 3d [2] 00 26 [2] 0f 3c [2] 11 21 [2] 13 20 [2] 08 26 [2] 14 21 [2] 08 0e }

  condition:
    any of them
}