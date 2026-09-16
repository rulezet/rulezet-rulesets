rule TTP_XOR_QUAD_CurrentVersionRun_6413 {
  strings:
    $key_6413 = { 37 7c [2] 13 72 [2] 38 5e [2] 16 7c [2] 02 67 [2] 0d 7d [2] 13 60 [2] 11 61 [2] 0a 67 [2] 16 60 [2] 0a 4f }

  condition:
    any of them
}