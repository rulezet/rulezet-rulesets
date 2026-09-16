rule TTP_XOR_QUAD_CurrentVersionRun_3913 {
  strings:
    $key_3913 = { 6a 7c [2] 4e 72 [2] 65 5e [2] 4b 7c [2] 5f 67 [2] 50 7d [2] 4e 60 [2] 4c 61 [2] 57 67 [2] 4b 60 [2] 57 4f }

  condition:
    any of them
}