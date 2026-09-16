rule TTP_XOR_QUAD_CurrentVersionRun_a7ec {
  strings:
    $key_a7ec = { f4 83 [2] d0 8d [2] fb a1 [2] d5 83 [2] c1 98 [2] ce 82 [2] d0 9f [2] d2 9e [2] c9 98 [2] d5 9f [2] c9 b0 }

  condition:
    any of them
}