rule TTP_XOR_QUAD_CurrentVersionRun_20ec {
  strings:
    $key_20ec = { 73 83 [2] 57 8d [2] 7c a1 [2] 52 83 [2] 46 98 [2] 49 82 [2] 57 9f [2] 55 9e [2] 4e 98 [2] 52 9f [2] 4e b0 }

  condition:
    any of them
}