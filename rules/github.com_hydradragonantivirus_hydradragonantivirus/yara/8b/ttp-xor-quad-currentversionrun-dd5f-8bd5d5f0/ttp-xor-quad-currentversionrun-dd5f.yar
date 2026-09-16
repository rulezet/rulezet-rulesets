rule TTP_XOR_QUAD_CurrentVersionRun_dd5f {
  strings:
    $key_dd5f = { 8e 30 [2] aa 3e [2] 81 12 [2] af 30 [2] bb 2b [2] b4 31 [2] aa 2c [2] a8 2d [2] b3 2b [2] af 2c [2] b3 03 }

  condition:
    any of them
}