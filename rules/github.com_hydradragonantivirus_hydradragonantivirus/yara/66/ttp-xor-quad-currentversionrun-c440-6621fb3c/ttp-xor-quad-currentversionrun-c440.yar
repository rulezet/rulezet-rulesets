rule TTP_XOR_QUAD_CurrentVersionRun_c440 {
  strings:
    $key_c440 = { 97 2f [2] b3 21 [2] 98 0d [2] b6 2f [2] a2 34 [2] ad 2e [2] b3 33 [2] b1 32 [2] aa 34 [2] b6 33 [2] aa 1c }

  condition:
    any of them
}