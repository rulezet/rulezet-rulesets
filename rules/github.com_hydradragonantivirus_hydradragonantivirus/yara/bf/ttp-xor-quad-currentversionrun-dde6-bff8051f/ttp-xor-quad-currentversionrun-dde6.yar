rule TTP_XOR_QUAD_CurrentVersionRun_dde6 {
  strings:
    $key_dde6 = { 8e 89 [2] aa 87 [2] 81 ab [2] af 89 [2] bb 92 [2] b4 88 [2] aa 95 [2] a8 94 [2] b3 92 [2] af 95 [2] b3 ba }

  condition:
    any of them
}