rule TTP_XOR_QUAD_CurrentVersionRun_6f13 {
  strings:
    $key_6f13 = { 3c 7c [2] 18 72 [2] 33 5e [2] 1d 7c [2] 09 67 [2] 06 7d [2] 18 60 [2] 1a 61 [2] 01 67 [2] 1d 60 [2] 01 4f }

  condition:
    any of them
}