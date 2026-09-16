rule TTP_XOR_QUAD_CurrentVersionRun_d710 {
  strings:
    $key_d710 = { 84 7f [2] a0 71 [2] 8b 5d [2] a5 7f [2] b1 64 [2] be 7e [2] a0 63 [2] a2 62 [2] b9 64 [2] a5 63 [2] b9 4c }

  condition:
    any of them
}