rule TTP_XOR_QUAD_CurrentVersionRun_0139 {
  strings:
    $key_0139 = { 52 56 [2] 76 58 [2] 5d 74 [2] 73 56 [2] 67 4d [2] 68 57 [2] 76 4a [2] 74 4b [2] 6f 4d [2] 73 4a [2] 6f 65 }

  condition:
    any of them
}