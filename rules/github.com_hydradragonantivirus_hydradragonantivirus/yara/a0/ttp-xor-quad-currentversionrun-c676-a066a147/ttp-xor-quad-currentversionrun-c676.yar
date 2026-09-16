rule TTP_XOR_QUAD_CurrentVersionRun_c676 {
  strings:
    $key_c676 = { 95 19 [2] b1 17 [2] 9a 3b [2] b4 19 [2] a0 02 [2] af 18 [2] b1 05 [2] b3 04 [2] a8 02 [2] b4 05 [2] a8 2a }

  condition:
    any of them
}