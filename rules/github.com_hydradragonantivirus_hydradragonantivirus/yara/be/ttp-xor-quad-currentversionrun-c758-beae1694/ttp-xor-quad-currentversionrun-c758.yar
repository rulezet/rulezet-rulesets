rule TTP_XOR_QUAD_CurrentVersionRun_c758 {
  strings:
    $key_c758 = { 94 37 [2] b0 39 [2] 9b 15 [2] b5 37 [2] a1 2c [2] ae 36 [2] b0 2b [2] b2 2a [2] a9 2c [2] b5 2b [2] a9 04 }

  condition:
    any of them
}