rule TTP_XOR_QUAD_CurrentVersionRun_0145 {
  strings:
    $key_0145 = { 52 2a [2] 76 24 [2] 5d 08 [2] 73 2a [2] 67 31 [2] 68 2b [2] 76 36 [2] 74 37 [2] 6f 31 [2] 73 36 [2] 6f 19 }

  condition:
    any of them
}