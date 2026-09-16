rule TTP_XOR_QUAD_CurrentVersionRun_f934 {
  strings:
    $key_f934 = { aa 5b [2] 8e 55 [2] a5 79 [2] 8b 5b [2] 9f 40 [2] 90 5a [2] 8e 47 [2] 8c 46 [2] 97 40 [2] 8b 47 [2] 97 68 }

  condition:
    any of them
}