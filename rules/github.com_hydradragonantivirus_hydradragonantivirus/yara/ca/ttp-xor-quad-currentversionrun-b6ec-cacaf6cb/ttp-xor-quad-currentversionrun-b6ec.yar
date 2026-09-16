rule TTP_XOR_QUAD_CurrentVersionRun_b6ec {
  strings:
    $key_b6ec = { e5 83 [2] c1 8d [2] ea a1 [2] c4 83 [2] d0 98 [2] df 82 [2] c1 9f [2] c3 9e [2] d8 98 [2] c4 9f [2] d8 b0 }

  condition:
    any of them
}