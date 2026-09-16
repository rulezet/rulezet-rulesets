rule TTP_XOR_QUAD_CurrentVersionRun_1bef {
  strings:
    $key_1bef = { 48 80 [2] 6c 8e [2] 47 a2 [2] 69 80 [2] 7d 9b [2] 72 81 [2] 6c 9c [2] 6e 9d [2] 75 9b [2] 69 9c [2] 75 b3 }

  condition:
    any of them
}