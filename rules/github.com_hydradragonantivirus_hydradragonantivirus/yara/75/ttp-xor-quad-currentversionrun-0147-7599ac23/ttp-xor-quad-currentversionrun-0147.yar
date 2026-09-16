rule TTP_XOR_QUAD_CurrentVersionRun_0147 {
  strings:
    $key_0147 = { 52 28 [2] 76 26 [2] 5d 0a [2] 73 28 [2] 67 33 [2] 68 29 [2] 76 34 [2] 74 35 [2] 6f 33 [2] 73 34 [2] 6f 1b }

  condition:
    any of them
}