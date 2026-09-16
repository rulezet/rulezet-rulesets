rule TTP_XOR_QUAD_CurrentVersionRun_3413 {
  strings:
    $key_3413 = { 67 7c [2] 43 72 [2] 68 5e [2] 46 7c [2] 52 67 [2] 5d 7d [2] 43 60 [2] 41 61 [2] 5a 67 [2] 46 60 [2] 5a 4f }

  condition:
    any of them
}