rule TTP_XOR_QUAD_CurrentVersionRun_c66b {
  strings:
    $key_c66b = { 95 04 [2] b1 0a [2] 9a 26 [2] b4 04 [2] a0 1f [2] af 05 [2] b1 18 [2] b3 19 [2] a8 1f [2] b4 18 [2] a8 37 }

  condition:
    any of them
}