rule TTP_XOR_QUAD_CurrentVersionRun_67ef {
  strings:
    $key_67ef = { 34 80 [2] 10 8e [2] 3b a2 [2] 15 80 [2] 01 9b [2] 0e 81 [2] 10 9c [2] 12 9d [2] 09 9b [2] 15 9c [2] 09 b3 }

  condition:
    any of them
}