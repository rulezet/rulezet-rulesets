rule TTP_XOR_QUAD_CurrentVersionRun_dfe5 {
  strings:
    $key_dfe5 = { 8c 8a [2] a8 84 [2] 83 a8 [2] ad 8a [2] b9 91 [2] b6 8b [2] a8 96 [2] aa 97 [2] b1 91 [2] ad 96 [2] b1 b9 }

  condition:
    any of them
}