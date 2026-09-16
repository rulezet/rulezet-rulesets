rule TTP_XOR_QUAD_CurrentVersionRun_d751 {
  strings:
    $key_d751 = { 84 3e [2] a0 30 [2] 8b 1c [2] a5 3e [2] b1 25 [2] be 3f [2] a0 22 [2] a2 23 [2] b9 25 [2] a5 22 [2] b9 0d }

  condition:
    any of them
}