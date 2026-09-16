rule TTP_XOR_QUAD_CurrentVersionRun_fcf5 {
  strings:
    $key_fcf5 = { af 9a [2] 8b 94 [2] a0 b8 [2] 8e 9a [2] 9a 81 [2] 95 9b [2] 8b 86 [2] 89 87 [2] 92 81 [2] 8e 86 [2] 92 a9 }

  condition:
    any of them
}