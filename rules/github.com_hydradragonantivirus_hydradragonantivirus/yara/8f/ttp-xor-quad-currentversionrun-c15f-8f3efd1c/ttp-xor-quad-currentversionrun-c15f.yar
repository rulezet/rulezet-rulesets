rule TTP_XOR_QUAD_CurrentVersionRun_c15f {
  strings:
    $key_c15f = { 92 30 [2] b6 3e [2] 9d 12 [2] b3 30 [2] a7 2b [2] a8 31 [2] b6 2c [2] b4 2d [2] af 2b [2] b3 2c [2] af 03 }

  condition:
    any of them
}