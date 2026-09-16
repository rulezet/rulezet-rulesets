rule TTP_XOR_QUAD_CurrentVersionRun_f3ec {
  strings:
    $key_f3ec = { a0 83 [2] 84 8d [2] af a1 [2] 81 83 [2] 95 98 [2] 9a 82 [2] 84 9f [2] 86 9e [2] 9d 98 [2] 81 9f [2] 9d b0 }

  condition:
    any of them
}