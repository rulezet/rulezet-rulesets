rule TTP_XOR_QUAD_CurrentVersionRun_d0ed {
  strings:
    $key_d0ed = { 83 82 [2] a7 8c [2] 8c a0 [2] a2 82 [2] b6 99 [2] b9 83 [2] a7 9e [2] a5 9f [2] be 99 [2] a2 9e [2] be b1 }

  condition:
    any of them
}