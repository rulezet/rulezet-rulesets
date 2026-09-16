rule TTP_XOR_QUAD_CurrentVersionRun_c3a2 {
  strings:
    $key_c3a2 = { 90 cd [2] b4 c3 [2] 9f ef [2] b1 cd [2] a5 d6 [2] aa cc [2] b4 d1 [2] b6 d0 [2] ad d6 [2] b1 d1 [2] ad fe }

  condition:
    any of them
}