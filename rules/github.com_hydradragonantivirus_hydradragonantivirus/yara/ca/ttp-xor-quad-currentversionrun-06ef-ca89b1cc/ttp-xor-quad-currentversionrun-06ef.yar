rule TTP_XOR_QUAD_CurrentVersionRun_06ef {
  strings:
    $key_06ef = { 55 80 [2] 71 8e [2] 5a a2 [2] 74 80 [2] 60 9b [2] 6f 81 [2] 71 9c [2] 73 9d [2] 68 9b [2] 74 9c [2] 68 b3 }

  condition:
    any of them
}