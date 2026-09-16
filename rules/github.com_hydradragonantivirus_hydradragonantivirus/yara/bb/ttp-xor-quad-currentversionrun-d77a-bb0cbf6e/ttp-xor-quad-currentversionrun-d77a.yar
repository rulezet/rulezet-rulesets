rule TTP_XOR_QUAD_CurrentVersionRun_d77a {
  strings:
    $key_d77a = { 84 15 [2] a0 1b [2] 8b 37 [2] a5 15 [2] b1 0e [2] be 14 [2] a0 09 [2] a2 08 [2] b9 0e [2] a5 09 [2] b9 26 }

  condition:
    any of them
}