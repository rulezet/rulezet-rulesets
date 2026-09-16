rule TTP_XOR_QUAD_CurrentVersionRun_ddf5 {
  strings:
    $key_ddf5 = { 8e 9a [2] aa 94 [2] 81 b8 [2] af 9a [2] bb 81 [2] b4 9b [2] aa 86 [2] a8 87 [2] b3 81 [2] af 86 [2] b3 a9 }

  condition:
    any of them
}