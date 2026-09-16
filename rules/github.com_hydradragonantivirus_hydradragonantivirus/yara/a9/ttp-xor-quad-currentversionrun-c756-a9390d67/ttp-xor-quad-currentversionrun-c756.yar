rule TTP_XOR_QUAD_CurrentVersionRun_c756 {
  strings:
    $key_c756 = { 94 39 [2] b0 37 [2] 9b 1b [2] b5 39 [2] a1 22 [2] ae 38 [2] b0 25 [2] b2 24 [2] a9 22 [2] b5 25 [2] a9 0a }

  condition:
    any of them
}