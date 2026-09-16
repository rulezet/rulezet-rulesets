rule TTP_XOR_QUAD_CurrentVersionRun_c72d {
  strings:
    $key_c72d = { 94 42 [2] b0 4c [2] 9b 60 [2] b5 42 [2] a1 59 [2] ae 43 [2] b0 5e [2] b2 5f [2] a9 59 [2] b5 5e [2] a9 71 }

  condition:
    any of them
}