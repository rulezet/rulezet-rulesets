rule TTP_XOR_QUAD_CurrentVersionRun_c658 {
  strings:
    $key_c658 = { 95 37 [2] b1 39 [2] 9a 15 [2] b4 37 [2] a0 2c [2] af 36 [2] b1 2b [2] b3 2a [2] a8 2c [2] b4 2b [2] a8 04 }

  condition:
    any of them
}