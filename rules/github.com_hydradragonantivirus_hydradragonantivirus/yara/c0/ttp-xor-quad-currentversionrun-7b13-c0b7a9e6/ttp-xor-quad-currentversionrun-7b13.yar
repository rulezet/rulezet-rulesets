rule TTP_XOR_QUAD_CurrentVersionRun_7b13 {
  strings:
    $key_7b13 = { 28 7c [2] 0c 72 [2] 27 5e [2] 09 7c [2] 1d 67 [2] 12 7d [2] 0c 60 [2] 0e 61 [2] 15 67 [2] 09 60 [2] 15 4f }

  condition:
    any of them
}