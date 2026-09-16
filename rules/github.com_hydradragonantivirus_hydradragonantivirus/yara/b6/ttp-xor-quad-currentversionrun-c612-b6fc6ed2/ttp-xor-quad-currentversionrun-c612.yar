rule TTP_XOR_QUAD_CurrentVersionRun_c612 {
  strings:
    $key_c612 = { 95 7d [2] b1 73 [2] 9a 5f [2] b4 7d [2] a0 66 [2] af 7c [2] b1 61 [2] b3 60 [2] a8 66 [2] b4 61 [2] a8 4e }

  condition:
    any of them
}