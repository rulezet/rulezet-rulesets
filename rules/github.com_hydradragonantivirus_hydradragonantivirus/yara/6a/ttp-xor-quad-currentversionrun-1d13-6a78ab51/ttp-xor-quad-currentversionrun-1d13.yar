rule TTP_XOR_QUAD_CurrentVersionRun_1d13 {
  strings:
    $key_1d13 = { 4e 7c [2] 6a 72 [2] 41 5e [2] 6f 7c [2] 7b 67 [2] 74 7d [2] 6a 60 [2] 68 61 [2] 73 67 [2] 6f 60 [2] 73 4f }

  condition:
    any of them
}