rule TTP_XOR_QUAD_CurrentVersionRun_f928 {
  strings:
    $key_f928 = { aa 47 [2] 8e 49 [2] a5 65 [2] 8b 47 [2] 9f 5c [2] 90 46 [2] 8e 5b [2] 8c 5a [2] 97 5c [2] 8b 5b [2] 97 74 }

  condition:
    any of them
}