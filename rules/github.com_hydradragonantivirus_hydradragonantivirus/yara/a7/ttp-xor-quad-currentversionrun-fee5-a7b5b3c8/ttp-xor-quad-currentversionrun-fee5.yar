rule TTP_XOR_QUAD_CurrentVersionRun_fee5 {
  strings:
    $key_fee5 = { ad 8a [2] 89 84 [2] a2 a8 [2] 8c 8a [2] 98 91 [2] 97 8b [2] 89 96 [2] 8b 97 [2] 90 91 [2] 8c 96 [2] 90 b9 }

  condition:
    any of them
}