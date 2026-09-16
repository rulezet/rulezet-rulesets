rule TTP_XOR_QUAD_CurrentVersionRun_dde4 {
  strings:
    $key_dde4 = { 8e 8b [2] aa 85 [2] 81 a9 [2] af 8b [2] bb 90 [2] b4 8a [2] aa 97 [2] a8 96 [2] b3 90 [2] af 97 [2] b3 b8 }

  condition:
    any of them
}