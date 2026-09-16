rule TTP_XOR_QUAD_CurrentVersionRun_dfa3 {
  strings:
    $key_dfa3 = { 8c cc [2] a8 c2 [2] 83 ee [2] ad cc [2] b9 d7 [2] b6 cd [2] a8 d0 [2] aa d1 [2] b1 d7 [2] ad d0 [2] b1 ff }

  condition:
    any of them
}