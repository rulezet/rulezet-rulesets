rule TTP_XOR_QUAD_CurrentVersionRun_d73d {
  strings:
    $key_d73d = { 84 52 [2] a0 5c [2] 8b 70 [2] a5 52 [2] b1 49 [2] be 53 [2] a0 4e [2] a2 4f [2] b9 49 [2] a5 4e [2] b9 61 }

  condition:
    any of them
}