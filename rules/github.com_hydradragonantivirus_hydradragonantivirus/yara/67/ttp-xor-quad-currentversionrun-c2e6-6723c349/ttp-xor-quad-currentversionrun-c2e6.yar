rule TTP_XOR_QUAD_CurrentVersionRun_c2e6 {
  strings:
    $key_c2e6 = { 91 89 [2] b5 87 [2] 9e ab [2] b0 89 [2] a4 92 [2] ab 88 [2] b5 95 [2] b7 94 [2] ac 92 [2] b0 95 [2] ac ba }

  condition:
    any of them
}