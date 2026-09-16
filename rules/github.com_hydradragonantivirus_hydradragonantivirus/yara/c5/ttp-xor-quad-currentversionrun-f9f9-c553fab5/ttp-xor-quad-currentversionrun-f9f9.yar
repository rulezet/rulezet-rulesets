rule TTP_XOR_QUAD_CurrentVersionRun_f9f9 {
  strings:
    $key_f9f9 = { aa 96 [2] 8e 98 [2] a5 b4 [2] 8b 96 [2] 9f 8d [2] 90 97 [2] 8e 8a [2] 8c 8b [2] 97 8d [2] 8b 8a [2] 97 a5 }

  condition:
    any of them
}