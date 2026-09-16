rule TTP_XOR_QUAD_CurrentVersionRun_c11a {
  strings:
    $key_c11a = { 92 75 [2] b6 7b [2] 9d 57 [2] b3 75 [2] a7 6e [2] a8 74 [2] b6 69 [2] b4 68 [2] af 6e [2] b3 69 [2] af 46 }

  condition:
    any of them
}