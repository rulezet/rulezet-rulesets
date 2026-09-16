rule TTP_XOR_QUAD_CurrentVersionRun_c602 {
  strings:
    $key_c602 = { 95 6d [2] b1 63 [2] 9a 4f [2] b4 6d [2] a0 76 [2] af 6c [2] b1 71 [2] b3 70 [2] a8 76 [2] b4 71 [2] a8 5e }

  condition:
    any of them
}