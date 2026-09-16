rule TTP_XOR_QUAD_CurrentVersionRun_2b13 {
  strings:
    $key_2b13 = { 78 7c [2] 5c 72 [2] 77 5e [2] 59 7c [2] 4d 67 [2] 42 7d [2] 5c 60 [2] 5e 61 [2] 45 67 [2] 59 60 [2] 45 4f }

  condition:
    any of them
}