rule TTP_XOR_QUAD_CurrentVersionRun_0178 {
  strings:
    $key_0178 = { 52 17 [2] 76 19 [2] 5d 35 [2] 73 17 [2] 67 0c [2] 68 16 [2] 76 0b [2] 74 0a [2] 6f 0c [2] 73 0b [2] 6f 24 }

  condition:
    any of them
}