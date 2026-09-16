rule TTP_XOR_QUAD_CurrentVersionRun_79ec {
  strings:
    $key_79ec = { 2a 83 [2] 0e 8d [2] 25 a1 [2] 0b 83 [2] 1f 98 [2] 10 82 [2] 0e 9f [2] 0c 9e [2] 17 98 [2] 0b 9f [2] 17 b0 }

  condition:
    any of them
}