rule TTP_XOR_QUAD_CurrentVersionRun_78ef {
  strings:
    $key_78ef = { 2b 80 [2] 0f 8e [2] 24 a2 [2] 0a 80 [2] 1e 9b [2] 11 81 [2] 0f 9c [2] 0d 9d [2] 16 9b [2] 0a 9c [2] 16 b3 }

  condition:
    any of them
}