rule TTP_XOR_QUAD_CurrentVersionRun_f913 {
  strings:
    $key_f913 = { aa 7c [2] 8e 72 [2] a5 5e [2] 8b 7c [2] 9f 67 [2] 90 7d [2] 8e 60 [2] 8c 61 [2] 97 67 [2] 8b 60 [2] 97 4f }

  condition:
    any of them
}