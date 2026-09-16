rule TTP_XOR_QUAD_CurrentVersionRun_f948 {
  strings:
    $key_f948 = { aa 27 [2] 8e 29 [2] a5 05 [2] 8b 27 [2] 9f 3c [2] 90 26 [2] 8e 3b [2] 8c 3a [2] 97 3c [2] 8b 3b [2] 97 14 }

  condition:
    any of them
}