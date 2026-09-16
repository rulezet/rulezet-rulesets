rule TTP_XOR_QUAD_CurrentVersionRun_d7ed {
  strings:
    $key_d7ed = { 84 82 [2] a0 8c [2] 8b a0 [2] a5 82 [2] b1 99 [2] be 83 [2] a0 9e [2] a2 9f [2] b9 99 [2] a5 9e [2] b9 b1 }

  condition:
    any of them
}