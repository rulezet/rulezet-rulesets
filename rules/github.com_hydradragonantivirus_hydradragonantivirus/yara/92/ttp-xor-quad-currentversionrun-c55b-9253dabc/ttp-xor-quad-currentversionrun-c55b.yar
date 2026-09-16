rule TTP_XOR_QUAD_CurrentVersionRun_c55b {
  strings:
    $key_c55b = { 96 34 [2] b2 3a [2] 99 16 [2] b7 34 [2] a3 2f [2] ac 35 [2] b2 28 [2] b0 29 [2] ab 2f [2] b7 28 [2] ab 07 }

  condition:
    any of them
}