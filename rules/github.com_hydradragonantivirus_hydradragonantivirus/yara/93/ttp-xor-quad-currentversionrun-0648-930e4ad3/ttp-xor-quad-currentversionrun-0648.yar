rule TTP_XOR_QUAD_CurrentVersionRun_0648 {
  strings:
    $key_0648 = { 55 27 [2] 71 29 [2] 5a 05 [2] 74 27 [2] 60 3c [2] 6f 26 [2] 71 3b [2] 73 3a [2] 68 3c [2] 74 3b [2] 68 14 }

  condition:
    any of them
}