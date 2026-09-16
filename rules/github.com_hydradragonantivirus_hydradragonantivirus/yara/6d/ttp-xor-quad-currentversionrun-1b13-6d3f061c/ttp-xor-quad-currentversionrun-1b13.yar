rule TTP_XOR_QUAD_CurrentVersionRun_1b13 {
  strings:
    $key_1b13 = { 48 7c [2] 6c 72 [2] 47 5e [2] 69 7c [2] 7d 67 [2] 72 7d [2] 6c 60 [2] 6e 61 [2] 75 67 [2] 69 60 [2] 75 4f }

  condition:
    any of them
}