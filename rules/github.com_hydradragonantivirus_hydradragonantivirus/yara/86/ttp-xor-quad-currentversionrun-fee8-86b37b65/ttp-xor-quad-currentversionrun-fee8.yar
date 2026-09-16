rule TTP_XOR_QUAD_CurrentVersionRun_fee8 {
  strings:
    $key_fee8 = { ad 87 [2] 89 89 [2] a2 a5 [2] 8c 87 [2] 98 9c [2] 97 86 [2] 89 9b [2] 8b 9a [2] 90 9c [2] 8c 9b [2] 90 b4 }

  condition:
    any of them
}