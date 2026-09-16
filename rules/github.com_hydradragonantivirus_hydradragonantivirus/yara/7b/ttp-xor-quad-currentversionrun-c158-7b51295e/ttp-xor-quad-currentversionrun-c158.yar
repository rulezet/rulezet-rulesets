rule TTP_XOR_QUAD_CurrentVersionRun_c158 {
  strings:
    $key_c158 = { 92 37 [2] b6 39 [2] 9d 15 [2] b3 37 [2] a7 2c [2] a8 36 [2] b6 2b [2] b4 2a [2] af 2c [2] b3 2b [2] af 04 }

  condition:
    any of them
}