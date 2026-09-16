rule TTP_XOR_QUAD_CurrentVersionRun_f957 {
  strings:
    $key_f957 = { aa 38 [2] 8e 36 [2] a5 1a [2] 8b 38 [2] 9f 23 [2] 90 39 [2] 8e 24 [2] 8c 25 [2] 97 23 [2] 8b 24 [2] 97 0b }

  condition:
    any of them
}