rule TTP_XOR_QUAD_CurrentVersionRun_c107 {
  strings:
    $key_c107 = { 92 68 [2] b6 66 [2] 9d 4a [2] b3 68 [2] a7 73 [2] a8 69 [2] b6 74 [2] b4 75 [2] af 73 [2] b3 74 [2] af 5b }

  condition:
    any of them
}