rule TTP_XOR_QUAD_CurrentVersionRun_5613 {
  strings:
    $key_5613 = { 05 7c [2] 21 72 [2] 0a 5e [2] 24 7c [2] 30 67 [2] 3f 7d [2] 21 60 [2] 23 61 [2] 38 67 [2] 24 60 [2] 38 4f }

  condition:
    any of them
}