rule TTP_XOR_QUAD_CurrentVersionRun_c77d {
  strings:
    $key_c77d = { 94 12 [2] b0 1c [2] 9b 30 [2] b5 12 [2] a1 09 [2] ae 13 [2] b0 0e [2] b2 0f [2] a9 09 [2] b5 0e [2] a9 21 }

  condition:
    any of them
}