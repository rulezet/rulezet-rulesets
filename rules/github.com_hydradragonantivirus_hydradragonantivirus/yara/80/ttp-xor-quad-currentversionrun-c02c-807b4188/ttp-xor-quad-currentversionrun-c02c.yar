rule TTP_XOR_QUAD_CurrentVersionRun_c02c {
  strings:
    $key_c02c = { 93 43 [2] b7 4d [2] 9c 61 [2] b2 43 [2] a6 58 [2] a9 42 [2] b7 5f [2] b5 5e [2] ae 58 [2] b2 5f [2] ae 70 }

  condition:
    any of them
}