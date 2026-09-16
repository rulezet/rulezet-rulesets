rule TTP_XOR_QUAD_CurrentVersionRun_0609 {
  strings:
    $key_0609 = { 55 66 [2] 71 68 [2] 5a 44 [2] 74 66 [2] 60 7d [2] 6f 67 [2] 71 7a [2] 73 7b [2] 68 7d [2] 74 7a [2] 68 55 }

  condition:
    any of them
}