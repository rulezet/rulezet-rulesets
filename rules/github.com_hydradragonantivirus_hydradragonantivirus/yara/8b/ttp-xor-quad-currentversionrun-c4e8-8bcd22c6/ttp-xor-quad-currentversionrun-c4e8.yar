rule TTP_XOR_QUAD_CurrentVersionRun_c4e8 {
  strings:
    $key_c4e8 = { 97 87 [2] b3 89 [2] 98 a5 [2] b6 87 [2] a2 9c [2] ad 86 [2] b3 9b [2] b1 9a [2] aa 9c [2] b6 9b [2] aa b4 }

  condition:
    any of them
}