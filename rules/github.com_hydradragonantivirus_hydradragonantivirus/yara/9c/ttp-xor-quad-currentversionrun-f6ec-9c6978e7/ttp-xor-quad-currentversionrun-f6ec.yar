rule TTP_XOR_QUAD_CurrentVersionRun_f6ec {
  strings:
    $key_f6ec = { a5 83 [2] 81 8d [2] aa a1 [2] 84 83 [2] 90 98 [2] 9f 82 [2] 81 9f [2] 83 9e [2] 98 98 [2] 84 9f [2] 98 b0 }

  condition:
    any of them
}