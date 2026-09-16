rule TTP_XOR_QUAD_CurrentVersionRun_dea2 {
  strings:
    $key_dea2 = { 8d cd [2] a9 c3 [2] 82 ef [2] ac cd [2] b8 d6 [2] b7 cc [2] a9 d1 [2] ab d0 [2] b0 d6 [2] ac d1 [2] b0 fe }

  condition:
    any of them
}