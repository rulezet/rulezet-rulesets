rule TTP_XOR_QUAD_CurrentVersionRun_c726 {
  strings:
    $key_c726 = { 94 49 [2] b0 47 [2] 9b 6b [2] b5 49 [2] a1 52 [2] ae 48 [2] b0 55 [2] b2 54 [2] a9 52 [2] b5 55 [2] a9 7a }

  condition:
    any of them
}