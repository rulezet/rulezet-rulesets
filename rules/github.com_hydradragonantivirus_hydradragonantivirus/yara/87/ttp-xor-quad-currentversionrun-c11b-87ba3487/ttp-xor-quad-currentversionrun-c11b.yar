rule TTP_XOR_QUAD_CurrentVersionRun_c11b {
  strings:
    $key_c11b = { 92 74 [2] b6 7a [2] 9d 56 [2] b3 74 [2] a7 6f [2] a8 75 [2] b6 68 [2] b4 69 [2] af 6f [2] b3 68 [2] af 47 }

  condition:
    any of them
}