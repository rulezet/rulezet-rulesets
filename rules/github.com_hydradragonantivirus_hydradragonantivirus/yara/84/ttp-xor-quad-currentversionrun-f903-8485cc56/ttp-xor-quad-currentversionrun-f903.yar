rule TTP_XOR_QUAD_CurrentVersionRun_f903 {
  strings:
    $key_f903 = { aa 6c [2] 8e 62 [2] a5 4e [2] 8b 6c [2] 9f 77 [2] 90 6d [2] 8e 70 [2] 8c 71 [2] 97 77 [2] 8b 70 [2] 97 5f }

  condition:
    any of them
}