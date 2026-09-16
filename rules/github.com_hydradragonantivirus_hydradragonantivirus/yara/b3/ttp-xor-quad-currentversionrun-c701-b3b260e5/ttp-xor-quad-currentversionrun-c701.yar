rule TTP_XOR_QUAD_CurrentVersionRun_c701 {
  strings:
    $key_c701 = { 94 6e [2] b0 60 [2] 9b 4c [2] b5 6e [2] a1 75 [2] ae 6f [2] b0 72 [2] b2 73 [2] a9 75 [2] b5 72 [2] a9 5d }

  condition:
    any of them
}