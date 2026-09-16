rule TTP_XOR_QUAD_CurrentVersionRun_c2d1 {
  strings:
    $key_c2d1 = { 91 be [2] b5 b0 [2] 9e 9c [2] b0 be [2] a4 a5 [2] ab bf [2] b5 a2 [2] b7 a3 [2] ac a5 [2] b0 a2 [2] ac 8d }

  condition:
    any of them
}