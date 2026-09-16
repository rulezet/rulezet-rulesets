rule TTP_XOR_QUAD_CurrentVersionRun_56ef {
  strings:
    $key_56ef = { 05 80 [2] 21 8e [2] 0a a2 [2] 24 80 [2] 30 9b [2] 3f 81 [2] 21 9c [2] 23 9d [2] 38 9b [2] 24 9c [2] 38 b3 }

  condition:
    any of them
}