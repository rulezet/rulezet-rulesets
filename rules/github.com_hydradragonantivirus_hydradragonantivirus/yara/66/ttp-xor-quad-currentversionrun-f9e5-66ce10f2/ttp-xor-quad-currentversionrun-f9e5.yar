rule TTP_XOR_QUAD_CurrentVersionRun_f9e5 {
  strings:
    $key_f9e5 = { aa 8a [2] 8e 84 [2] a5 a8 [2] 8b 8a [2] 9f 91 [2] 90 8b [2] 8e 96 [2] 8c 97 [2] 97 91 [2] 8b 96 [2] 97 b9 }

  condition:
    any of them
}