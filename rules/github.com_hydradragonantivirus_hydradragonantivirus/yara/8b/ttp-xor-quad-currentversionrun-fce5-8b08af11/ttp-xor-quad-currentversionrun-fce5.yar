rule TTP_XOR_QUAD_CurrentVersionRun_fce5 {
  strings:
    $key_fce5 = { af 8a [2] 8b 84 [2] a0 a8 [2] 8e 8a [2] 9a 91 [2] 95 8b [2] 8b 96 [2] 89 97 [2] 92 91 [2] 8e 96 [2] 92 b9 }

  condition:
    any of them
}