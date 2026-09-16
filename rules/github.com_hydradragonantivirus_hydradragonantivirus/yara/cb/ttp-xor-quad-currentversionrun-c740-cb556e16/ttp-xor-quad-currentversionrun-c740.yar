rule TTP_XOR_QUAD_CurrentVersionRun_c740 {
  strings:
    $key_c740 = { 94 2f [2] b0 21 [2] 9b 0d [2] b5 2f [2] a1 34 [2] ae 2e [2] b0 33 [2] b2 32 [2] a9 34 [2] b5 33 [2] a9 1c }

  condition:
    any of them
}