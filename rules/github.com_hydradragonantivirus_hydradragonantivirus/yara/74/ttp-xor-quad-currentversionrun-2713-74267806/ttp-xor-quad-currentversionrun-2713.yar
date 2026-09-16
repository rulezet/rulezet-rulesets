rule TTP_XOR_QUAD_CurrentVersionRun_2713 {
  strings:
    $key_2713 = { 74 7c [2] 50 72 [2] 7b 5e [2] 55 7c [2] 41 67 [2] 4e 7d [2] 50 60 [2] 52 61 [2] 49 67 [2] 55 60 [2] 49 4f }

  condition:
    any of them
}