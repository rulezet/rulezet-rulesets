rule TTP_XOR_QUAD_CurrentVersionRun_f9e8 {
  strings:
    $key_f9e8 = { aa 87 [2] 8e 89 [2] a5 a5 [2] 8b 87 [2] 9f 9c [2] 90 86 [2] 8e 9b [2] 8c 9a [2] 97 9c [2] 8b 9b [2] 97 b4 }

  condition:
    any of them
}