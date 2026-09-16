rule TTP_XOR_QUAD_CurrentVersionRun_d1a2 {
  strings:
    $key_d1a2 = { 82 cd [2] a6 c3 [2] 8d ef [2] a3 cd [2] b7 d6 [2] b8 cc [2] a6 d1 [2] a4 d0 [2] bf d6 [2] a3 d1 [2] bf fe }

  condition:
    any of them
}