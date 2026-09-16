rule TTP_XOR_QUAD_CurrentVersionRun_deb2 {
  strings:
    $key_deb2 = { 8d dd [2] a9 d3 [2] 82 ff [2] ac dd [2] b8 c6 [2] b7 dc [2] a9 c1 [2] ab c0 [2] b0 c6 [2] ac c1 [2] b0 ee }

  condition:
    any of them
}