rule TTP_XOR_QUAD_CurrentVersionRun_26ec {
  strings:
    $key_26ec = { 75 83 [2] 51 8d [2] 7a a1 [2] 54 83 [2] 40 98 [2] 4f 82 [2] 51 9f [2] 53 9e [2] 48 98 [2] 54 9f [2] 48 b0 }

  condition:
    any of them
}