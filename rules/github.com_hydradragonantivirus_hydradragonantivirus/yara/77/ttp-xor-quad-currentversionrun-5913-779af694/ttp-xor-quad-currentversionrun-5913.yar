rule TTP_XOR_QUAD_CurrentVersionRun_5913 {
  strings:
    $key_5913 = { 0a 7c [2] 2e 72 [2] 05 5e [2] 2b 7c [2] 3f 67 [2] 30 7d [2] 2e 60 [2] 2c 61 [2] 37 67 [2] 2b 60 [2] 37 4f }

  condition:
    any of them
}