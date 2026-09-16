rule TTP_XOR_QUAD_CurrentVersionRun_d733 {
  strings:
    $key_d733 = { 84 5c [2] a0 52 [2] 8b 7e [2] a5 5c [2] b1 47 [2] be 5d [2] a0 40 [2] a2 41 [2] b9 47 [2] a5 40 [2] b9 6f }

  condition:
    any of them
}