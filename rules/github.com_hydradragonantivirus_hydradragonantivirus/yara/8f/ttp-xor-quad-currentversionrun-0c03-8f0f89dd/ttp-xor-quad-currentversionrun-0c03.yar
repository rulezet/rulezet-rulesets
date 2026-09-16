rule TTP_XOR_QUAD_CurrentVersionRun_0c03 {
  strings:
    $key_0c03 = { 5f 6c [2] 7b 62 [2] 50 4e [2] 7e 6c [2] 6a 77 [2] 65 6d [2] 7b 70 [2] 79 71 [2] 62 77 [2] 7e 70 [2] 62 5f }

  condition:
    any of them
}