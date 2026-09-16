rule TTP_XOR_QUAD_CurrentVersionRun_d7a2 {
  strings:
    $key_d7a2 = { 84 cd [2] a0 c3 [2] 8b ef [2] a5 cd [2] b1 d6 [2] be cc [2] a0 d1 [2] a2 d0 [2] b9 d6 [2] a5 d1 [2] b9 fe }

  condition:
    any of them
}