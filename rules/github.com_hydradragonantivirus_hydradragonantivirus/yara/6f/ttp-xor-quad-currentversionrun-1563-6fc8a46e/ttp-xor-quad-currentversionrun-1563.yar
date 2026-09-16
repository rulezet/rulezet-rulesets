rule TTP_XOR_QUAD_CurrentVersionRun_1563 {
  strings:
    $key_1563 = { 46 0c [2] 62 02 [2] 49 2e [2] 67 0c [2] 73 17 [2] 7c 0d [2] 62 10 [2] 60 11 [2] 7b 17 [2] 67 10 [2] 7b 3f }

  condition:
    any of them
}