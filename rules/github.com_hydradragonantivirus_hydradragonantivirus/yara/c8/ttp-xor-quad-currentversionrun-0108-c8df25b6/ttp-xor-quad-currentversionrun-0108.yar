rule TTP_XOR_QUAD_CurrentVersionRun_0108 {
  strings:
    $key_0108 = { 52 67 [2] 76 69 [2] 5d 45 [2] 73 67 [2] 67 7c [2] 68 66 [2] 76 7b [2] 74 7a [2] 6f 7c [2] 73 7b [2] 6f 54 }

  condition:
    any of them
}