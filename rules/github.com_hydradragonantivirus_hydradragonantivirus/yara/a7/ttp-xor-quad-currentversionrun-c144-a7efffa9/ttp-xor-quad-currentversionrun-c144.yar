rule TTP_XOR_QUAD_CurrentVersionRun_c144 {
  strings:
    $key_c144 = { 92 2b [2] b6 25 [2] 9d 09 [2] b3 2b [2] a7 30 [2] a8 2a [2] b6 37 [2] b4 36 [2] af 30 [2] b3 37 [2] af 18 }

  condition:
    any of them
}