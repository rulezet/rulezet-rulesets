rule TTP_XOR_QUAD_CurrentVersionRun_c0ea {
  strings:
    $key_c0ea = { 93 85 [2] b7 8b [2] 9c a7 [2] b2 85 [2] a6 9e [2] a9 84 [2] b7 99 [2] b5 98 [2] ae 9e [2] b2 99 [2] ae b6 }

  condition:
    any of them
}