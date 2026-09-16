rule TTP_XOR_QUAD_CurrentVersionRun_fdec {
  strings:
    $key_fdec = { ae 83 [2] 8a 8d [2] a1 a1 [2] 8f 83 [2] 9b 98 [2] 94 82 [2] 8a 9f [2] 88 9e [2] 93 98 [2] 8f 9f [2] 93 b0 }

  condition:
    any of them
}