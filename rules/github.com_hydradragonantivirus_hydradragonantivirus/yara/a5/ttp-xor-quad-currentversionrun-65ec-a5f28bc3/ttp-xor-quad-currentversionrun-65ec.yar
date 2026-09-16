rule TTP_XOR_QUAD_CurrentVersionRun_65ec {
  strings:
    $key_65ec = { 36 83 [2] 12 8d [2] 39 a1 [2] 17 83 [2] 03 98 [2] 0c 82 [2] 12 9f [2] 10 9e [2] 0b 98 [2] 17 9f [2] 0b b0 }

  condition:
    any of them
}