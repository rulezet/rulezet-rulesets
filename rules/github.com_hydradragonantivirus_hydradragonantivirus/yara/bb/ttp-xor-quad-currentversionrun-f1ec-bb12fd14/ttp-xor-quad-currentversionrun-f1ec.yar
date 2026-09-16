rule TTP_XOR_QUAD_CurrentVersionRun_f1ec {
  strings:
    $key_f1ec = { a2 83 [2] 86 8d [2] ad a1 [2] 83 83 [2] 97 98 [2] 98 82 [2] 86 9f [2] 84 9e [2] 9f 98 [2] 83 9f [2] 9f b0 }

  condition:
    any of them
}