rule TTP_XOR_QUAD_CurrentVersionRun_1e03 {
  strings:
    $key_1e03 = { 4d 6c [2] 69 62 [2] 42 4e [2] 6c 6c [2] 78 77 [2] 77 6d [2] 69 70 [2] 6b 71 [2] 70 77 [2] 6c 70 [2] 70 5f }

  condition:
    any of them
}