rule TTP_XOR_QUAD_CurrentVersionRun_f937 {
  strings:
    $key_f937 = { aa 58 [2] 8e 56 [2] a5 7a [2] 8b 58 [2] 9f 43 [2] 90 59 [2] 8e 44 [2] 8c 45 [2] 97 43 [2] 8b 44 [2] 97 6b }

  condition:
    any of them
}