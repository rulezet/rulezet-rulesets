rule TTP_XOR_QUAD_CurrentVersionRun_e8ec {
  strings:
    $key_e8ec = { bb 83 [2] 9f 8d [2] b4 a1 [2] 9a 83 [2] 8e 98 [2] 81 82 [2] 9f 9f [2] 9d 9e [2] 86 98 [2] 9a 9f [2] 86 b0 }

  condition:
    any of them
}