rule TTP_XOR_QUAD_CurrentVersionRun_c4e5 {
  strings:
    $key_c4e5 = { 97 8a [2] b3 84 [2] 98 a8 [2] b6 8a [2] a2 91 [2] ad 8b [2] b3 96 [2] b1 97 [2] aa 91 [2] b6 96 [2] aa b9 }

  condition:
    any of them
}