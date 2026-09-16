rule TTP_XOR_QUAD_CurrentVersionRun_c25b {
  strings:
    $key_c25b = { 91 34 [2] b5 3a [2] 9e 16 [2] b0 34 [2] a4 2f [2] ab 35 [2] b5 28 [2] b7 29 [2] ac 2f [2] b0 28 [2] ac 07 }

  condition:
    any of them
}