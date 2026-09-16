rule TTP_XOR_QUAD_CurrentVersionRun_37ec {
  strings:
    $key_37ec = { 64 83 [2] 40 8d [2] 6b a1 [2] 45 83 [2] 51 98 [2] 5e 82 [2] 40 9f [2] 42 9e [2] 59 98 [2] 45 9f [2] 59 b0 }

  condition:
    any of them
}