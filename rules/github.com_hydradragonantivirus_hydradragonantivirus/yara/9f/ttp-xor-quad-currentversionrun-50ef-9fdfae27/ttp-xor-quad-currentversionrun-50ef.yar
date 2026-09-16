rule TTP_XOR_QUAD_CurrentVersionRun_50ef {
  strings:
    $key_50ef = { 03 80 [2] 27 8e [2] 0c a2 [2] 22 80 [2] 36 9b [2] 39 81 [2] 27 9c [2] 25 9d [2] 3e 9b [2] 22 9c [2] 3e b3 }

  condition:
    any of them
}