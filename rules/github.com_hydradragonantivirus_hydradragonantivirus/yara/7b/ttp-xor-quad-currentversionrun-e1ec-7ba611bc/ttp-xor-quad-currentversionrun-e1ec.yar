rule TTP_XOR_QUAD_CurrentVersionRun_e1ec {
  strings:
    $key_e1ec = { b2 83 [2] 96 8d [2] bd a1 [2] 93 83 [2] 87 98 [2] 88 82 [2] 96 9f [2] 94 9e [2] 8f 98 [2] 93 9f [2] 8f b0 }

  condition:
    any of them
}