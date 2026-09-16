rule TTP_XOR_QUAD_CurrentVersionRun_c242 {
  strings:
    $key_c242 = { 91 2d [2] b5 23 [2] 9e 0f [2] b0 2d [2] a4 36 [2] ab 2c [2] b5 31 [2] b7 30 [2] ac 36 [2] b0 31 [2] ac 1e }

  condition:
    any of them
}