rule TTP_XOR_QUAD_CurrentVersionRun_d7f3 {
  strings:
    $key_d7f3 = { 84 9c [2] a0 92 [2] 8b be [2] a5 9c [2] b1 87 [2] be 9d [2] a0 80 [2] a2 81 [2] b9 87 [2] a5 80 [2] b9 af }

  condition:
    any of them
}