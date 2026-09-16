rule TTP_XOR_QUAD_CurrentVersionRun_c73c {
  strings:
    $key_c73c = { 94 53 [2] b0 5d [2] 9b 71 [2] b5 53 [2] a1 48 [2] ae 52 [2] b0 4f [2] b2 4e [2] a9 48 [2] b5 4f [2] a9 60 }

  condition:
    any of them
}