rule TTP_XOR_QUAD_CurrentVersionRun_0bef {
  strings:
    $key_0bef = { 58 80 [2] 7c 8e [2] 57 a2 [2] 79 80 [2] 6d 9b [2] 62 81 [2] 7c 9c [2] 7e 9d [2] 65 9b [2] 79 9c [2] 65 b3 }

  condition:
    any of them
}