rule TTP_XOR_QUAD_CurrentVersionRun_c55f {
  strings:
    $key_c55f = { 96 30 [2] b2 3e [2] 99 12 [2] b7 30 [2] a3 2b [2] ac 31 [2] b2 2c [2] b0 2d [2] ab 2b [2] b7 2c [2] ab 03 }

  condition:
    any of them
}