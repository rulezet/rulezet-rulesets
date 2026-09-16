rule TTP_XOR_QUAD_CurrentVersionRun_c617 {
  strings:
    $key_c617 = { 95 78 [2] b1 76 [2] 9a 5a [2] b4 78 [2] a0 63 [2] af 79 [2] b1 64 [2] b3 65 [2] a8 63 [2] b4 64 [2] a8 4b }

  condition:
    any of them
}