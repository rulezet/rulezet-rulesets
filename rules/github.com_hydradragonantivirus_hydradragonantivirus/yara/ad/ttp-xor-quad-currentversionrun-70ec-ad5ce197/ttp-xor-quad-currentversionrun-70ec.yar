rule TTP_XOR_QUAD_CurrentVersionRun_70ec {
  strings:
    $key_70ec = { 23 83 [2] 07 8d [2] 2c a1 [2] 02 83 [2] 16 98 [2] 19 82 [2] 07 9f [2] 05 9e [2] 1e 98 [2] 02 9f [2] 1e b0 }

  condition:
    any of them
}