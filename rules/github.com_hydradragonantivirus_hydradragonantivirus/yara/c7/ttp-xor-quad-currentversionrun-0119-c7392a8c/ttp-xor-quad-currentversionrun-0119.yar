rule TTP_XOR_QUAD_CurrentVersionRun_0119 {
  strings:
    $key_0119 = { 52 76 [2] 76 78 [2] 5d 54 [2] 73 76 [2] 67 6d [2] 68 77 [2] 76 6a [2] 74 6b [2] 6f 6d [2] 73 6a [2] 6f 45 }

  condition:
    any of them
}