rule TTP_XOR_QUAD_CurrentVersionRun_f2ec {
  strings:
    $key_f2ec = { a1 83 [2] 85 8d [2] ae a1 [2] 80 83 [2] 94 98 [2] 9b 82 [2] 85 9f [2] 87 9e [2] 9c 98 [2] 80 9f [2] 9c b0 }

  condition:
    any of them
}