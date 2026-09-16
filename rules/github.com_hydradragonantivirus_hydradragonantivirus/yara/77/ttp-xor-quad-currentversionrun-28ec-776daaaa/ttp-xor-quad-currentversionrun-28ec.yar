rule TTP_XOR_QUAD_CurrentVersionRun_28ec {
  strings:
    $key_28ec = { 7b 83 [2] 5f 8d [2] 74 a1 [2] 5a 83 [2] 4e 98 [2] 41 82 [2] 5f 9f [2] 5d 9e [2] 46 98 [2] 5a 9f [2] 46 b0 }

  condition:
    any of them
}