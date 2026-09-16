rule TTP_XOR_QUAD_CurrentVersionRun_c291 {
  strings:
    $key_c291 = { 91 fe [2] b5 f0 [2] 9e dc [2] b0 fe [2] a4 e5 [2] ab ff [2] b5 e2 [2] b7 e3 [2] ac e5 [2] b0 e2 [2] ac cd }

  condition:
    any of them
}