rule TTP_XOR_QUAD_CurrentVersionRun_3613 {
  strings:
    $key_3613 = { 65 7c [2] 41 72 [2] 6a 5e [2] 44 7c [2] 50 67 [2] 5f 7d [2] 41 60 [2] 43 61 [2] 58 67 [2] 44 60 [2] 58 4f }

  condition:
    any of them
}