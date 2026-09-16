rule TTP_XOR_QUAD_CurrentVersionRun_0127 {
  strings:
    $key_0127 = { 52 48 [2] 76 46 [2] 5d 6a [2] 73 48 [2] 67 53 [2] 68 49 [2] 76 54 [2] 74 55 [2] 6f 53 [2] 73 54 [2] 6f 7b }

  condition:
    any of them
}