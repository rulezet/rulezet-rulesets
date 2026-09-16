rule TTP_XOR_QUAD_CurrentVersionRun_c4e9 {
  strings:
    $key_c4e9 = { 97 86 [2] b3 88 [2] 98 a4 [2] b6 86 [2] a2 9d [2] ad 87 [2] b3 9a [2] b1 9b [2] aa 9d [2] b6 9a [2] aa b5 }

  condition:
    any of them
}