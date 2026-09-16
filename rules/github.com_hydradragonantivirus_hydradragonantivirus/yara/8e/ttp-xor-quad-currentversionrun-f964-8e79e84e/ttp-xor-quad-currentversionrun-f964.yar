rule TTP_XOR_QUAD_CurrentVersionRun_f964 {
  strings:
    $key_f964 = { aa 0b [2] 8e 05 [2] a5 29 [2] 8b 0b [2] 9f 10 [2] 90 0a [2] 8e 17 [2] 8c 16 [2] 97 10 [2] 8b 17 [2] 97 38 }

  condition:
    any of them
}