rule TTP_XOR_QUAD_CurrentVersionRun_d74a {
  strings:
    $key_d74a = { 84 25 [2] a0 2b [2] 8b 07 [2] a5 25 [2] b1 3e [2] be 24 [2] a0 39 [2] a2 38 [2] b9 3e [2] a5 39 [2] b9 16 }

  condition:
    any of them
}