rule TTP_XOR_QUAD_CurrentVersionRun_fce8 {
  strings:
    $key_fce8 = { af 87 [2] 8b 89 [2] a0 a5 [2] 8e 87 [2] 9a 9c [2] 95 86 [2] 8b 9b [2] 89 9a [2] 92 9c [2] 8e 9b [2] 92 b4 }

  condition:
    any of them
}