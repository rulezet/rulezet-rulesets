rule TTP_XOR_QUAD_CurrentVersionRun_d766 {
  strings:
    $key_d766 = { 84 09 [2] a0 07 [2] 8b 2b [2] a5 09 [2] b1 12 [2] be 08 [2] a0 15 [2] a2 14 [2] b9 12 [2] a5 15 [2] b9 3a }

  condition:
    any of them
}