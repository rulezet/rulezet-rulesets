rule TTP_XOR_QUAD_CurrentVersionRun_d71a {
  strings:
    $key_d71a = { 84 75 [2] a0 7b [2] 8b 57 [2] a5 75 [2] b1 6e [2] be 74 [2] a0 69 [2] a2 68 [2] b9 6e [2] a5 69 [2] b9 46 }

  condition:
    any of them
}