rule TTP_XOR_QUAD_CurrentVersionRun_d073 {
  strings:
    $key_d073 = { 83 1c [2] a7 12 [2] 8c 3e [2] a2 1c [2] b6 07 [2] b9 1d [2] a7 00 [2] a5 01 [2] be 07 [2] a2 00 [2] be 2f }

  condition:
    any of them
}