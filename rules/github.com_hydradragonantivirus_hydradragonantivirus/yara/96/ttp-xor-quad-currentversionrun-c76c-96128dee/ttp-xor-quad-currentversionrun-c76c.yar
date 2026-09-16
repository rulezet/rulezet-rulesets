rule TTP_XOR_QUAD_CurrentVersionRun_c76c {
  strings:
    $key_c76c = { 94 03 [2] b0 0d [2] 9b 21 [2] b5 03 [2] a1 18 [2] ae 02 [2] b0 1f [2] b2 1e [2] a9 18 [2] b5 1f [2] a9 30 }

  condition:
    any of them
}