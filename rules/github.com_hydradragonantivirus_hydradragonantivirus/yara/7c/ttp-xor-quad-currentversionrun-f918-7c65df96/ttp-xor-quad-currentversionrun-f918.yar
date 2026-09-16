rule TTP_XOR_QUAD_CurrentVersionRun_f918 {
  strings:
    $key_f918 = { aa 77 [2] 8e 79 [2] a5 55 [2] 8b 77 [2] 9f 6c [2] 90 76 [2] 8e 6b [2] 8c 6a [2] 97 6c [2] 8b 6b [2] 97 44 }

  condition:
    any of them
}