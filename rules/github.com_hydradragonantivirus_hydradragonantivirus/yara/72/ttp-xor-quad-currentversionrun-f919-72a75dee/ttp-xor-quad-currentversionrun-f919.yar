rule TTP_XOR_QUAD_CurrentVersionRun_f919 {
  strings:
    $key_f919 = { aa 76 [2] 8e 78 [2] a5 54 [2] 8b 76 [2] 9f 6d [2] 90 77 [2] 8e 6a [2] 8c 6b [2] 97 6d [2] 8b 6a [2] 97 45 }

  condition:
    any of them
}