rule TTP_XOR_QUAD_CurrentVersionRun_c17a {
  strings:
    $key_c17a = { 92 15 [2] b6 1b [2] 9d 37 [2] b3 15 [2] a7 0e [2] a8 14 [2] b6 09 [2] b4 08 [2] af 0e [2] b3 09 [2] af 26 }

  condition:
    any of them
}