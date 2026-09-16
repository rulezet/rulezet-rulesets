rule TTP_XOR_QUAD_CurrentVersionRun_f925 {
  strings:
    $key_f925 = { aa 4a [2] 8e 44 [2] a5 68 [2] 8b 4a [2] 9f 51 [2] 90 4b [2] 8e 56 [2] 8c 57 [2] 97 51 [2] 8b 56 [2] 97 79 }

  condition:
    any of them
}