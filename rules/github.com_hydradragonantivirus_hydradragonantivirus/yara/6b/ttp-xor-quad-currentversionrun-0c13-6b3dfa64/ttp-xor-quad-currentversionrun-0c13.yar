rule TTP_XOR_QUAD_CurrentVersionRun_0c13 {
  strings:
    $key_0c13 = { 5f 7c [2] 7b 72 [2] 50 5e [2] 7e 7c [2] 6a 67 [2] 65 7d [2] 7b 60 [2] 79 61 [2] 62 67 [2] 7e 60 [2] 62 4f }

  condition:
    any of them
}