rule TTP_XOR_QUAD_CurrentVersionRun_d73a {
  strings:
    $key_d73a = { 84 55 [2] a0 5b [2] 8b 77 [2] a5 55 [2] b1 4e [2] be 54 [2] a0 49 [2] a2 48 [2] b9 4e [2] a5 49 [2] b9 66 }

  condition:
    any of them
}