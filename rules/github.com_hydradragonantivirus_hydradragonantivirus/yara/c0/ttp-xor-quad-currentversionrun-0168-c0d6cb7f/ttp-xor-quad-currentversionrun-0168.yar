rule TTP_XOR_QUAD_CurrentVersionRun_0168 {
  strings:
    $key_0168 = { 52 07 [2] 76 09 [2] 5d 25 [2] 73 07 [2] 67 1c [2] 68 06 [2] 76 1b [2] 74 1a [2] 6f 1c [2] 73 1b [2] 6f 34 }

  condition:
    any of them
}