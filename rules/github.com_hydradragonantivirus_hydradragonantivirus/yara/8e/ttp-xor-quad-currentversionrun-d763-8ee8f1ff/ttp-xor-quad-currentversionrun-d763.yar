rule TTP_XOR_QUAD_CurrentVersionRun_d763 {
  strings:
    $key_d763 = { 84 0c [2] a0 02 [2] 8b 2e [2] a5 0c [2] b1 17 [2] be 0d [2] a0 10 [2] a2 11 [2] b9 17 [2] a5 10 [2] b9 3f }

  condition:
    any of them
}