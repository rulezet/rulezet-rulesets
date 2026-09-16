rule TTP_XOR_QUAD_CurrentVersionRun_c7a2 {
  strings:
    $key_c7a2 = { 94 cd [2] b0 c3 [2] 9b ef [2] b5 cd [2] a1 d6 [2] ae cc [2] b0 d1 [2] b2 d0 [2] a9 d6 [2] b5 d1 [2] a9 fe }

  condition:
    any of them
}