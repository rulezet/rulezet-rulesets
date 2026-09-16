rule TTP_XOR_QUAD_CurrentVersionRun_c443 {
  strings:
    $key_c443 = { 97 2c [2] b3 22 [2] 98 0e [2] b6 2c [2] a2 37 [2] ad 2d [2] b3 30 [2] b1 31 [2] aa 37 [2] b6 30 [2] aa 1f }

  condition:
    any of them
}