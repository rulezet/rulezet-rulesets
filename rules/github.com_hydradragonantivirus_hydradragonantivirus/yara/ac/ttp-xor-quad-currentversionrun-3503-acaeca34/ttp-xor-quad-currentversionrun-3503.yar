rule TTP_XOR_QUAD_CurrentVersionRun_3503 {
  strings:
    $key_3503 = { 66 6c [2] 42 62 [2] 69 4e [2] 47 6c [2] 53 77 [2] 5c 6d [2] 42 70 [2] 40 71 [2] 5b 77 [2] 47 70 [2] 5b 5f }

  condition:
    any of them
}