rule TTP_XOR_QUAD_CurrentVersionRun_c656 {
  strings:
    $key_c656 = { 95 39 [2] b1 37 [2] 9a 1b [2] b4 39 [2] a0 22 [2] af 38 [2] b1 25 [2] b3 24 [2] a8 22 [2] b4 25 [2] a8 0a }

  condition:
    any of them
}