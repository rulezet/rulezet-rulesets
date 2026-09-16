rule TTP_XOR_QUAD_CurrentVersionRun_c71a {
  strings:
    $key_c71a = { 94 75 [2] b0 7b [2] 9b 57 [2] b5 75 [2] a1 6e [2] ae 74 [2] b0 69 [2] b2 68 [2] a9 6e [2] b5 69 [2] a9 46 }

  condition:
    any of them
}