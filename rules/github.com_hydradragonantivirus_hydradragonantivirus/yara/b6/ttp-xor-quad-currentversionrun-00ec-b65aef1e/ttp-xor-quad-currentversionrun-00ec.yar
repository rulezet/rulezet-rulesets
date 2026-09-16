rule TTP_XOR_QUAD_CurrentVersionRun_00ec {
  strings:
    $key_00ec = { 53 83 [2] 77 8d [2] 5c a1 [2] 72 83 [2] 66 98 [2] 69 82 [2] 77 9f [2] 75 9e [2] 6e 98 [2] 72 9f [2] 6e b0 }

  condition:
    any of them
}