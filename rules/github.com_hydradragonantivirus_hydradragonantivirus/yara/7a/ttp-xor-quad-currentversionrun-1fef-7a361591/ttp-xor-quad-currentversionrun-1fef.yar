rule TTP_XOR_QUAD_CurrentVersionRun_1fef {
  strings:
    $key_1fef = { 4c 80 [2] 68 8e [2] 43 a2 [2] 6d 80 [2] 79 9b [2] 76 81 [2] 68 9c [2] 6a 9d [2] 71 9b [2] 6d 9c [2] 71 b3 }

  condition:
    any of them
}