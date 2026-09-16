rule TTP_XOR_QUAD_CurrentVersionRun_fded {
  strings:
    $key_fded = { ae 82 [2] 8a 8c [2] a1 a0 [2] 8f 82 [2] 9b 99 [2] 94 83 [2] 8a 9e [2] 88 9f [2] 93 99 [2] 8f 9e [2] 93 b1 }

  condition:
    any of them
}