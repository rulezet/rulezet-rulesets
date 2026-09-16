rule TTP_XOR_QUAD_CurrentVersionRun_5ffa {
  strings:
    $key_5ffa = { 0c 95 [2] 28 9b [2] 03 b7 [2] 2d 95 [2] 39 8e [2] 36 94 [2] 28 89 [2] 2a 88 [2] 31 8e [2] 2d 89 [2] 31 a6 }

  condition:
    any of them
}