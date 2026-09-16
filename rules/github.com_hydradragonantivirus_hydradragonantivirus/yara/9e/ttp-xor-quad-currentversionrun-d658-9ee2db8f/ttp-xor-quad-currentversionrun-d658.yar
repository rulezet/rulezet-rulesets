rule TTP_XOR_QUAD_CurrentVersionRun_d658 {
  strings:
    $key_d658 = { 85 37 [2] a1 39 [2] 8a 15 [2] a4 37 [2] b0 2c [2] bf 36 [2] a1 2b [2] a3 2a [2] b8 2c [2] a4 2b [2] b8 04 }

  condition:
    any of them
}