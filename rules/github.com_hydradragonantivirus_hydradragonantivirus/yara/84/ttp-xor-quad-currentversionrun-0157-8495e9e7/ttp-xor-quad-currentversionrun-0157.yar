rule TTP_XOR_QUAD_CurrentVersionRun_0157 {
  strings:
    $key_0157 = { 52 38 [2] 76 36 [2] 5d 1a [2] 73 38 [2] 67 23 [2] 68 39 [2] 76 24 [2] 74 25 [2] 6f 23 [2] 73 24 [2] 6f 0b }

  condition:
    any of them
}