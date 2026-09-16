rule TTP_XOR_QUAD_CurrentVersionRun_1013 {
  strings:
    $key_1013 = { 43 7c [2] 67 72 [2] 4c 5e [2] 62 7c [2] 76 67 [2] 79 7d [2] 67 60 [2] 65 61 [2] 7e 67 [2] 62 60 [2] 7e 4f }

  condition:
    any of them
}