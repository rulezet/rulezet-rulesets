rule TTP_XOR_QUAD_CurrentVersionRun_01c4 {
  strings:
    $key_01c4 = { 52 ab [2] 76 a5 [2] 5d 89 [2] 73 ab [2] 67 b0 [2] 68 aa [2] 76 b7 [2] 74 b6 [2] 6f b0 [2] 73 b7 [2] 6f 98 }

  condition:
    any of them
}