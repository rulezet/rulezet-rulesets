rule TTP_XOR_QUAD_CurrentVersionRun_de42 {
  strings:
    $key_de42 = { 8d 2d [2] a9 23 [2] 82 0f [2] ac 2d [2] b8 36 [2] b7 2c [2] a9 31 [2] ab 30 [2] b0 36 [2] ac 31 [2] b0 1e }

  condition:
    any of them
}