rule TTP_XOR_QUAD_CurrentVersionRun_c73b {
  strings:
    $key_c73b = { 94 54 [2] b0 5a [2] 9b 76 [2] b5 54 [2] a1 4f [2] ae 55 [2] b0 48 [2] b2 49 [2] a9 4f [2] b5 48 [2] a9 67 }

  condition:
    any of them
}