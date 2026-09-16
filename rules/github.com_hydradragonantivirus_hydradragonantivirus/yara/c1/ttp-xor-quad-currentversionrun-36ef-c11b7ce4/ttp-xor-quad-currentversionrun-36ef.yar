rule TTP_XOR_QUAD_CurrentVersionRun_36ef {
  strings:
    $key_36ef = { 65 80 [2] 41 8e [2] 6a a2 [2] 44 80 [2] 50 9b [2] 5f 81 [2] 41 9c [2] 43 9d [2] 58 9b [2] 44 9c [2] 58 b3 }

  condition:
    any of them
}