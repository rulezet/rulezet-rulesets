rule TTP_XOR_QUAD_CurrentVersionRun_0179 {
  strings:
    $key_0179 = { 52 16 [2] 76 18 [2] 5d 34 [2] 73 16 [2] 67 0d [2] 68 17 [2] 76 0a [2] 74 0b [2] 6f 0d [2] 73 0a [2] 6f 25 }

  condition:
    any of them
}