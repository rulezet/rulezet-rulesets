rule TTP_XOR_QUAD_CurrentVersionRun_3003 {
  strings:
    $key_3003 = { 63 6c [2] 47 62 [2] 6c 4e [2] 42 6c [2] 56 77 [2] 59 6d [2] 47 70 [2] 45 71 [2] 5e 77 [2] 42 70 [2] 5e 5f }

  condition:
    any of them
}