rule TTP_XOR_QUAD_CurrentVersionRun_c1e8 {
  strings:
    $key_c1e8 = { 92 87 [2] b6 89 [2] 9d a5 [2] b3 87 [2] a7 9c [2] a8 86 [2] b6 9b [2] b4 9a [2] af 9c [2] b3 9b [2] af b4 }

  condition:
    any of them
}