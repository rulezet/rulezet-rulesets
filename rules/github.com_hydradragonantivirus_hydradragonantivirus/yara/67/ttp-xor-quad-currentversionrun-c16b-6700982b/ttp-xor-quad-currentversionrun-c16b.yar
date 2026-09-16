rule TTP_XOR_QUAD_CurrentVersionRun_c16b {
  strings:
    $key_c16b = { 92 04 [2] b6 0a [2] 9d 26 [2] b3 04 [2] a7 1f [2] a8 05 [2] b6 18 [2] b4 19 [2] af 1f [2] b3 18 [2] af 37 }

  condition:
    any of them
}