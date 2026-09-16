rule TTP_XOR_QUAD_CurrentVersionRun_2649 {
  strings:
    $key_2649 = { 75 26 [2] 51 28 [2] 7a 04 [2] 54 26 [2] 40 3d [2] 4f 27 [2] 51 3a [2] 53 3b [2] 48 3d [2] 54 3a [2] 48 15 }

  condition:
    any of them
}