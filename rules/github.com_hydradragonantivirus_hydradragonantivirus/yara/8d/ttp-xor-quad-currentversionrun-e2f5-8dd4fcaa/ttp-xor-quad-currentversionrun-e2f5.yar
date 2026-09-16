rule TTP_XOR_QUAD_CurrentVersionRun_e2f5 {
  strings:
    $key_e2f5 = { b1 9a [2] 95 94 [2] be b8 [2] 90 9a [2] 84 81 [2] 8b 9b [2] 95 86 [2] 97 87 [2] 8c 81 [2] 90 86 [2] 8c a9 }

  condition:
    any of them
}