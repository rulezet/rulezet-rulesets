rule TTP_XOR_QUAD_CurrentVersionRun_c5e6 {
  strings:
    $key_c5e6 = { 96 89 [2] b2 87 [2] 99 ab [2] b7 89 [2] a3 92 [2] ac 88 [2] b2 95 [2] b0 94 [2] ab 92 [2] b7 95 [2] ab ba }

  condition:
    any of them
}