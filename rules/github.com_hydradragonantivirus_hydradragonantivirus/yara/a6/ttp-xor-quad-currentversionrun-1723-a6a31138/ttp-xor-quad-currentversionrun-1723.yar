rule TTP_XOR_QUAD_CurrentVersionRun_1723 {
  strings:
    $key_1723 = { 44 4c [2] 60 42 [2] 4b 6e [2] 65 4c [2] 71 57 [2] 7e 4d [2] 60 50 [2] 62 51 [2] 79 57 [2] 65 50 [2] 79 7f }

  condition:
    any of them
}