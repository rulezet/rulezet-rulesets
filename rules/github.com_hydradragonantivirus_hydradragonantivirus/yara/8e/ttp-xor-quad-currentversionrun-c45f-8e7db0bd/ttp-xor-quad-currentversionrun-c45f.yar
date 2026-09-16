rule TTP_XOR_QUAD_CurrentVersionRun_c45f {
  strings:
    $key_c45f = { 97 30 [2] b3 3e [2] 98 12 [2] b6 30 [2] a2 2b [2] ad 31 [2] b3 2c [2] b1 2d [2] aa 2b [2] b6 2c [2] aa 03 }

  condition:
    any of them
}