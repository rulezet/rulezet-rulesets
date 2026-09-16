rule TTP_XOR_QUAD_CurrentVersionRun_d6a2 {
  strings:
    $key_d6a2 = { 85 cd [2] a1 c3 [2] 8a ef [2] a4 cd [2] b0 d6 [2] bf cc [2] a1 d1 [2] a3 d0 [2] b8 d6 [2] a4 d1 [2] b8 fe }

  condition:
    any of them
}