rule TTP_XOR_QUAD_CurrentVersionRun_c1e2 {
  strings:
    $key_c1e2 = { 92 8d [2] b6 83 [2] 9d af [2] b3 8d [2] a7 96 [2] a8 8c [2] b6 91 [2] b4 90 [2] af 96 [2] b3 91 [2] af be }

  condition:
    any of them
}