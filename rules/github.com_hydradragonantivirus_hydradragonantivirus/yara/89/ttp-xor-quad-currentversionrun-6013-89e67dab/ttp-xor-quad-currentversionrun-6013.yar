rule TTP_XOR_QUAD_CurrentVersionRun_6013 {
  strings:
    $key_6013 = { 33 7c [2] 17 72 [2] 3c 5e [2] 12 7c [2] 06 67 [2] 09 7d [2] 17 60 [2] 15 61 [2] 0e 67 [2] 12 60 [2] 0e 4f }

  condition:
    any of them
}