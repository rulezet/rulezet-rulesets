rule TTP_XOR_QUAD_CurrentVersionRun_0713 {
  strings:
    $key_0713 = { 54 7c [2] 70 72 [2] 5b 5e [2] 75 7c [2] 61 67 [2] 6e 7d [2] 70 60 [2] 72 61 [2] 69 67 [2] 75 60 [2] 69 4f }

  condition:
    any of them
}