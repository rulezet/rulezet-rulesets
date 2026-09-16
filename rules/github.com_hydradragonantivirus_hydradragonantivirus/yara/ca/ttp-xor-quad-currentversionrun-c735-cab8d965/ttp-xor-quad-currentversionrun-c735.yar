rule TTP_XOR_QUAD_CurrentVersionRun_c735 {
  strings:
    $key_c735 = { 94 5a [2] b0 54 [2] 9b 78 [2] b5 5a [2] a1 41 [2] ae 5b [2] b0 46 [2] b2 47 [2] a9 41 [2] b5 46 [2] a9 69 }

  condition:
    any of them
}