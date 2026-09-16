rule TTP_XOR_QUAD_CurrentVersionRun_f923 {
  strings:
    $key_f923 = { aa 4c [2] 8e 42 [2] a5 6e [2] 8b 4c [2] 9f 57 [2] 90 4d [2] 8e 50 [2] 8c 51 [2] 97 57 [2] 8b 50 [2] 97 7f }

  condition:
    any of them
}