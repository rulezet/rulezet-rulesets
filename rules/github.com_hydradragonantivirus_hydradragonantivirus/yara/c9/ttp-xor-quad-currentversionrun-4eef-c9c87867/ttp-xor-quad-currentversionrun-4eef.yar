rule TTP_XOR_QUAD_CurrentVersionRun_4eef {
  strings:
    $key_4eef = { 1d 80 [2] 39 8e [2] 12 a2 [2] 3c 80 [2] 28 9b [2] 27 81 [2] 39 9c [2] 3b 9d [2] 20 9b [2] 3c 9c [2] 20 b3 }

  condition:
    any of them
}