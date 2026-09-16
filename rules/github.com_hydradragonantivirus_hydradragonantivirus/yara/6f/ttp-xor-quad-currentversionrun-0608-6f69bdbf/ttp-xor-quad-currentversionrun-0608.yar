rule TTP_XOR_QUAD_CurrentVersionRun_0608 {
  strings:
    $key_0608 = { 55 67 [2] 71 69 [2] 5a 45 [2] 74 67 [2] 60 7c [2] 6f 66 [2] 71 7b [2] 73 7a [2] 68 7c [2] 74 7b [2] 68 54 }

  condition:
    any of them
}