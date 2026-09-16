rule TTP_XOR_QUAD_CurrentVersionRun_46ef {
  strings:
    $key_46ef = { 15 80 [2] 31 8e [2] 1a a2 [2] 34 80 [2] 20 9b [2] 2f 81 [2] 31 9c [2] 33 9d [2] 28 9b [2] 34 9c [2] 28 b3 }

  condition:
    any of them
}