rule TTP_XOR_QUAD_CurrentVersionRun_3113 {
  strings:
    $key_3113 = { 62 7c [2] 46 72 [2] 6d 5e [2] 43 7c [2] 57 67 [2] 58 7d [2] 46 60 [2] 44 61 [2] 5f 67 [2] 43 60 [2] 5f 4f }

  condition:
    any of them
}