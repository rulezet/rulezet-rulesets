rule TTP_XOR_QUAD_CurrentVersionRun_0503 {
  strings:
    $key_0503 = { 56 6c [2] 72 62 [2] 59 4e [2] 77 6c [2] 63 77 [2] 6c 6d [2] 72 70 [2] 70 71 [2] 6b 77 [2] 77 70 [2] 6b 5f }

  condition:
    any of them
}