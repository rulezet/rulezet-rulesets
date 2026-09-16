rule TTP_XOR_QUAD_CurrentVersionRun_c168 {
  strings:
    $key_c168 = { 92 07 [2] b6 09 [2] 9d 25 [2] b3 07 [2] a7 1c [2] a8 06 [2] b6 1b [2] b4 1a [2] af 1c [2] b3 1b [2] af 34 }

  condition:
    any of them
}