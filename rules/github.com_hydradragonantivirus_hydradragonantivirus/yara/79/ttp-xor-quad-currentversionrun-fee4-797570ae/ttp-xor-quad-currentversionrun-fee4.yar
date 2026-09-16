rule TTP_XOR_QUAD_CurrentVersionRun_fee4 {
  strings:
    $key_fee4 = { ad 8b [2] 89 85 [2] a2 a9 [2] 8c 8b [2] 98 90 [2] 97 8a [2] 89 97 [2] 8b 96 [2] 90 90 [2] 8c 97 [2] 90 b8 }

  condition:
    any of them
}