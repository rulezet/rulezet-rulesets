rule TTP_XOR_QUAD_CurrentVersionRun_d0f4 {
  strings:
    $key_d0f4 = { 83 9b [2] a7 95 [2] 8c b9 [2] a2 9b [2] b6 80 [2] b9 9a [2] a7 87 [2] a5 86 [2] be 80 [2] a2 87 [2] be a8 }

  condition:
    any of them
}