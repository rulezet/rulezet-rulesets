rule TTP_XOR_QUAD_CurrentVersionRun_53c5 {
  strings:
    $key_53c5 = { 00 aa [2] 24 a4 [2] 0f 88 [2] 21 aa [2] 35 b1 [2] 3a ab [2] 24 b6 [2] 26 b7 [2] 3d b1 [2] 21 b6 [2] 3d 99 }

  condition:
    any of them
}