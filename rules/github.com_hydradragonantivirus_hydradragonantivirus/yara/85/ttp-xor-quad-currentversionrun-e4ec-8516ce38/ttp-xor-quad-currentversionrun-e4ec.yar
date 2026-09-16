rule TTP_XOR_QUAD_CurrentVersionRun_e4ec {
  strings:
    $key_e4ec = { b7 83 [2] 93 8d [2] b8 a1 [2] 96 83 [2] 82 98 [2] 8d 82 [2] 93 9f [2] 91 9e [2] 8a 98 [2] 96 9f [2] 8a b0 }

  condition:
    any of them
}