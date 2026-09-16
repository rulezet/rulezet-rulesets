rule TTP_XOR_QUAD_CurrentVersionRun_dde5 {
  strings:
    $key_dde5 = { 8e 8a [2] aa 84 [2] 81 a8 [2] af 8a [2] bb 91 [2] b4 8b [2] aa 96 [2] a8 97 [2] b3 91 [2] af 96 [2] b3 b9 }

  condition:
    any of them
}